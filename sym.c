#define	MODULE
#define	__KERNEL__
#define	__KERNEL_SYSCALLS__
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sys.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/elf.h>
#include <linux/string.h>
#include "include/kdbg.h"

static so_t so[SYM_SO_N] = {0};

static int sym_load(char *so_name, unsigned int base);
static int sym_so_load(so_t *_so);
static so_t *sym_so_find(char *so_name);
static unsigned int sym_find_by_name(char *_name);
static int sym_find_by_val(unsigned int val, char *name);

extern char *path2name(char *path);
extern int ntask;


static unsigned int sym_find_in_so_by_name(so_t *_so, char *name)
{
	int len;
	sym_t **sym = _so->sym;
	while (sym < _so->sym + _so->nsym) {
		if (!strcmp((*sym)->name, name))
			return (*sym)->val + _so->base;
		sym++;
	}
	len = strlen(name);
	sym = _so->sym;
	while (sym < _so->sym + _so->nsym) {
		if (!strncmp((*sym)->name, name, len))
			return (*sym)->val + _so->base;
		sym++;
	}
	return 0;
}

static unsigned int sym_find_by_name(char *_name)
{
	so_t *_so = so;
	sym_t **sym;
	char *sym_name;
	char name[128];
	int i;
	
	strncpy(name, _name, 128);
	for (sym_name = name; *sym_name && (*sym_name != '!'); sym_name++) {}
	if (*sym_name == '!') {
		*(sym_name++) = 0;
		_so = sym_so_find(name);
		if (!_so)
			return 0;
		return sym_find_in_so_by_name(_so, sym_name);
	}
	
	for (i=0; i < SYM_SO_N; i++) {
		unsigned int sval;
		if (so[i].name[0]) {
			sval = sym_find_in_so_by_name(&so[i], name);
			if (sval)
				return sval;
		}
	}
	return 0;
}

static int sym_find_by_val(unsigned int val, char *name)
{
	so_t *_so;
	unsigned int _val;
	sym_t **sym;
	int i;

	for (i=0; i < SYM_SO_N; i++) {
		_so = &so[i];
		if (!_so->name[0])
			continue;
		_val = val - _so->base;
		sym = _so->sym;
		while (sym < _so->sym + _so->nsym) {
			if ((*sym)->val == _val) {
				if (strncmp((*sym)->name, "gcc2_compiled.", 14)) {
					*name = 0;
					if (_so->base) {
						strcat(name, path2name(_so->name));
						strcat(name, "!");
					}
					strcat(name, (*sym)->name);
					return 1;
				}
			}
			sym++;
		}
	}
	return 0;
}

static int do_sym_load(char *so_name, unsigned int so_base)
{
	int i;

	if (sym_so_find(so_name)) {
		print("Symbolic information from %s is already loaded\n", so_name);
		return -1;
	}

	for (i=0; i < SYM_SO_N && so[i].name[0]; i++)
		if (i == SYM_SO_N)
			return 0;
	memset(&so[i], 0, sizeof(so[i]));

	so[i].base = so_base;
	strncpy(so[i].name, so_name, 60);
	return i;
}

static int sym_load(char *so_name, unsigned int so_base)
{
	int i = do_sym_load(so_name, so_base);
	if (i >= 0)
		sym_so_load(&so[i]);
	return i;
}

static int schedule_sym_load(char *so_name, unsigned int so_base)
{
	int i = do_sym_load(so_name, so_base);
	if (i >= 0) {
		print("Queuing loading symbolic information from %s...\n", so_name);
		_schedule_task(sym_so_load, &so[i]);
	}
	return i;
}


static int sym_so_load(so_t *_so)
{	
	int i, j;
	struct file *f;
	int sh_sym = 0;
	int sh_str = 0;
	int strtab_s;
	struct elfhdr hdr;
	Elf32_Shdr *shdr;
	struct elf32_sym symtab;
	char strtab[128];	
	static char *err_mem = "kdbg: Not enough memory for loading symbolic information\n";

	ntask--;

	f = filp_open(_so->name, O_ACCMODE, O_RDONLY);
	if (IS_ERR(f)) {
		print("kdbg: Can't open file %s\n", _so->name);
		memset(_so, 0, sizeof(*_so));
		return -1;
	}
	
	kernel_read(f, 0, (char *)&hdr, sizeof(hdr));
	shdr = (Elf32_Shdr *)kmalloc(hdr.e_shnum * hdr.e_shentsize, GFP_KERNEL);
	if (!shdr) {
		print(err_mem);
		memset(_so, 0, sizeof(*_so));
		return -1;
	}

	kernel_read(f, hdr.e_shoff, (char *)shdr, hdr.e_shnum * hdr.e_shentsize);
	for(i=0;i < hdr.e_shnum; i++) {
		if (shdr[i].sh_type == SHT_SYMTAB) {
			sh_sym = i;
			_so->nsym = shdr[i].sh_size / sizeof(struct elf32_sym);
		}
		if (shdr[i].sh_type == SHT_STRTAB) {
			sh_str = i;
			strtab_s = shdr[i].sh_size;
		}
	}
	if (!sh_sym || !sh_str) {
		filp_close(f, current->files);
		kfree(shdr);
		print("kdbg: No symbolic information in %s\n", _so->name);
		memset(_so, 0, sizeof(*_so));
		return -1;
	}


	_so->sym = (sym_t **)kmalloc(_so->nsym * sizeof(sym_t *), GFP_KERNEL);
	if (!shdr) {
		kfree(shdr);
		print(err_mem);
		filp_close(f, current->files);
		memset(_so, 0, sizeof(*_so));
		return -1;
	}

	for (i = 0; i < _so->nsym; i+=MAX_SYM_SLAB) {

		_so->sym[i] = (sym_t *)kmalloc(MAX_SYM_SLAB*sizeof(sym_t), GFP_KERNEL);

		if (!_so->sym[i]) {
			int j;
			for (j = 0; j < i; j+=MAX_SYM_SLAB)
				kfree(_so->sym[j]);
			print(err_mem);
			filp_close(f, current->files);
			memset(_so, 0, sizeof(*_so));
			return -1;
		}

		for (j = i+1; j < i + MAX_SYM_SLAB; j++)
			_so->sym[j] = _so->sym[j-1] + 1;
	}

	print("kdbg: Loading symbols from %s (base == 0x%08lX)\n", _so->name, _so->base);
	
	for (i = 0; i < _so->nsym; i++) {
		kernel_read(f, shdr[sh_sym].sh_offset + i * sizeof(struct elf32_sym),
				(char *)&symtab, sizeof(struct elf32_sym));

		if (!symtab.st_value)
			continue;

		if ((symtab.st_name) && (symtab.st_name + 32 < strtab_s)) {
			kernel_read(f, shdr[sh_str].sh_offset + symtab.st_name,
					strtab, 128);
			strncpy(_so->sym[i]->name, strtab, 27);
			_so->sym[i]->name[27] = 0;
			_so->sym[i]->val = symtab.st_value;
		}
	}
	print("kdbg: 0x%08lX symbols loaded.\n", _so->nsym);

	kfree(shdr);
	filp_close(f, current->files);
	return 0;
}

static so_t *sym_so_find(char *so_name)
{
	int i;
	if (!so_name)
		return 0;
	for (i=0; i < SYM_SO_N; i++)
		if (so[i].name[0])
			if (!strcmp(path2name(so[i].name), path2name(so_name)))
				return &so[i];
	for (i=0; i < SYM_SO_N; i++)
		if (so[i].name[0])
			if (!strncmp(path2name(so[i].name),
						path2name(so_name), 2))
				return &so[i];
	return 0;
}

static void sym_so_clean(char *name)
{
	int i;
	so_t *_so = sym_so_find(name);
	if (_so->sym) {
		for (i = 0; i < _so->nsym; i+=MAX_SYM_SLAB)
			if (_so->sym[i])
				kfree(_so->sym[i]);
		kfree(_so->sym);
	}
	memset(&so[i], 0, sizeof(so_t));
}

static void sym_clean()
{
	int i, j;
	for (i=0; i < SYM_SO_N; i++)
		if (so[i].sym) {
			for (j = 0; j < so[i].nsym; j+=MAX_SYM_SLAB)
				if (so[i].sym[j])
					kfree(so[i].sym[j]);
			kfree(so[i].sym);
		}
}
