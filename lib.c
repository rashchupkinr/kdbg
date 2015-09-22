#define	MODULE
#define	__KERNEL__
#define	__KERNEL_SYSCALLS__
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sys.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/fs.h>
#include <linux/console.h>
#include <asm/uaccess.h>
#include <linux/string.h>
#include "disasm/disasm.h"
#include "include/kdbg.h"

extern volatile int status;
extern struct pt_regs *regs;
extern unsigned int esp0;
extern unsigned int ss0;

extern int sym_find_by_val(unsigned int, char *);

static int print(char *fmt, ...);
static void dump(char *addr, int len);
static int disasm(unsigned int addr, char *buf);
static unsigned int str2int(char *buf);
static int is_sym(char c);
static int file_write(struct file *file, char *buf, unsigned int len,
			unsigned int pos);	// append if pos == -1
static char *_strcpy(char *dest, const char *src);
static int _schedule_task(void (*routine)(void *), void *data);
static char *path2name(char *path);

static struct file *log_file = 0;
static struct tq_struct task[32];
static volatile int ntask = 0;

static int _schedule_task(void (*routine)(void *), void *data)
{
	if (ntask == 31)
		return -1;

	ntask++;

	task[ntask].sync = 0;
	task[ntask].routine = routine;
	task[ntask].data = data;
	schedule_task(&task[ntask]);
	return 0;
}

static unsigned int *get_pesp()
{
	if (regs->eip >= __PAGE_OFFSET)
		return &esp0;
	else
		return (unsigned int *)&regs->esp;
}

static unsigned int *get_pss()
{
	if (regs->eip >= __PAGE_OFFSET)
		return &ss0;
	else
		return (unsigned int *)&regs->xss;
}

static int print(char *fmt, ...)
{
	char *buf = (char *)kmalloc(0x1000, GFP_KERNEL | GFP_ATOMIC);
	va_list ap;
	va_start(ap, fmt);
	vsprintf(buf, fmt, ap);

	if (log_file)
		file_write(log_file, buf, strlen(buf), -1);

	printk(buf);
	kfree(buf);
}

static int file_write(struct file *file, char *buf, unsigned int len,
		      unsigned int pos)
{
	mm_segment_t old_fs;
	
	if (!(file->f_op && file->f_op->write))
		return	-1;
	file->f_pos = 0;
	if (pos != -1)
		file->f_pos = pos;
	old_fs = get_fs();
	set_fs(get_ds());
	file->f_op->write(file, buf, len, &file->f_pos);
	set_fs(old_fs);
	return 0;
}

static void dump(char *addr, int len)
{
	char *tmp;
	int i, j;

	if (!mem_can_read_rgn(addr, len))
		return;

	for (tmp = addr; tmp < addr + len;) {
		print("%08lX | ", (long) tmp);
		for (i = 0; i < 4; i++) {
			for (j = 0; j < 4; j++) {
				if (tmp + 4*i+j < addr + len)
					print("%02lX ",
						(unsigned char) tmp[i * 4 + j]);
				else
					print("   ");
			}
			print(" ");
		}
		print("\b| ");
		for (j = 0; j < 16; j++) {
			if (tmp <= addr + len)
				if (*tmp >= ' ' && *tmp <= '~')
					print("%c", *tmp);
				else
					print(".");
			tmp++;
		}
		print("\n");
	}
}

static char *dec2int(char *buf, unsigned int *n)
{
	int i;
	for (i = 0;i <= 8;i++) {
		if (*buf == ' ' || *buf == 0)
			return buf;
		if (*buf >= '0' && *buf <= '9')
			*n = *n * 10 + (*buf - '0');
		else
			break;
		buf++;
	}
	return buf;
}

static char *hex2int(char *buf, unsigned int *n)
{
	unsigned int i, j;
	char *hex = "0123456789abcdef!";
	char *HEX = "0123456789ABCDEF!";
	i = j = *n = 0;

	for (i = 0;i <= 8;i++) {
		if (*buf == ' ' || *buf == 0)
			return buf;
		for (j=0;j<0x10;j++)
			if ((*buf == hex[j]) || (*buf == HEX[j]))
				break;
		if (j != 0x10)
			*n = *n * 16 + j;
		else
			break;
		buf++;
	}
	return buf;
}

static unsigned int str2int(char *buf)
{
	unsigned int n = 0;
	int i = 0;
	int j;
	int from_mem = 0;
	char _buf[0x100] = {0};
	
	while (*buf == ' ')
		buf++;
	
	if (*buf == '[') {
		from_mem = 1;
		buf++;
	}

	for (j=0;j < strlen(buf) && j < 0x100;j++)
		if (buf[j] && buf[j] != ' ' && buf[j] != '+' &&
			buf[j] != '-' && buf[j] != '*' && buf[j] != '/')
			_buf[j] = buf[j];
		else 
			break;
	if (j >= 3 && (n = sym_find_by_name(_buf)))
		buf += j; 
	else if (!strncmp(buf, "eax", 3)) {	n = regs->eax;	buf += 3; }
	else if (!strncmp(buf, "ecx", 3)) {	n = regs->ecx;	buf += 3; }
	else if (!strncmp(buf, "edx", 3)) {	n = regs->edx;	buf += 3; }
	else if (!strncmp(buf, "ebx", 3)) {	n = regs->ebx;	buf += 3; }
	else if (!strncmp(buf, "ebp", 3)) {	n = regs->ebp;	buf += 3; }
	else if (!strncmp(buf, "esp", 3)) {	n = *get_pesp();buf += 3; }
	else if (!strncmp(buf, "esi", 3)) {	n = regs->esi;	buf += 3; }
	else if (!strncmp(buf, "edi", 3)) {	n = regs->edi;	buf += 3; }
	else if (!strncmp(buf, "eip", 3)) {	n = regs->eip;	buf += 3; }
	else {
		if (!strncmp(buf, "0x", 2))
			buf += 2;
		buf = hex2int(buf, &n);
	}

	switch (*buf) {
	case '+':	n += str2int(buf + 1);	break;
	case '-':	n -= str2int(buf + 1);	break;
	case '*':	n *= str2int(buf + 1);	break;
	case '&':	n &= str2int(buf + 1);	break;
	case '|':	n |= str2int(buf + 1);	break;
	case '/':{
			unsigned int m = str2int(buf + 1);
			if (m)
				n /= m;
			break;
		}
	}

	if (from_mem)	{
		if (mem_can_read(n))
			n = *(unsigned int *)n;
		else
			n = 0;
	}
	return n;
}

static char *_strcpy(char *dest, const char *src)
{
	while (*dest++ = *src++);
	return dest;
}

static int is_sym(char c)
{
	int i;
	char *syms = " +-*/&|?><[]_#@$~.!";
	if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')
		|| (c >= 'A' && c <= 'Z'))
		return 1;
	for (i = 0; i < strlen(syms); i++)
		if (c == syms[i])
			return 1;
	return 0;
}

static char *disasm_buf __asm__("disasm_buf");
static char *disasm_cur_buf __asm__("disasm_cur_buf");
static unsigned int fprintf_ret __asm__("fprintf_ret");
static int disasm_read_memory(bfd_vma memaddr, bfd_byte * myaddr,
			      int length, struct disassemble_info *info)
{
	if (mem_can_read(memaddr))
		memcpy(myaddr, (void *)memaddr, length);
	return 0;
}

static void disasm_print_address(bfd_vma addr, struct disassemble_info *info)
{
	char buf[128] = {0};
	disasm_cur_buf +=
		sprintf((char *) disasm_cur_buf, "0x%08lX", (long) addr);
	if (sym_find_by_val(addr, buf)) {
		int max_len = disasm_buf + 80 - disasm_cur_buf - 2;
		if (max_len > strlen(buf))
			max_len = strlen(buf);
		*disasm_cur_buf++ = '<';
		*disasm_cur_buf=0;
		 strncat(disasm_cur_buf, buf, max_len);
		 disasm_cur_buf += max_len;
		*disasm_cur_buf++ = '>';
	}
}

static disasm_fprintf()
{
	__asm__("popl	(fprintf_ret)\n"
		"popl	%eax\n"
		"pushl	disasm_cur_buf\n"
		"call	sprintf\n"
		"addl	%eax, disasm_cur_buf\n"
		"jmp	*fprintf_ret\n");
}

static int disasm(unsigned int addr, char *buf)
{
	struct disassemble_info di = {0};

	di.mach = bfd_mach_i386_i386;
	di.fprintf_func = (fprintf_ftype)&disasm_fprintf;
	di.print_address_func = disasm_print_address;
	di.read_memory_func = disasm_read_memory;
	disasm_buf = disasm_cur_buf = buf;
	return print_insn_i386(addr, &di);
}

static int is_call_inst(unsigned int eip)
{
	unsigned char c1, c2;
	c1 = *(unsigned char *)eip;
	c2 = (*((unsigned char *)eip + 1) & 0x38) >> 3;
	if (c1 == 0xE8 || c1 == 0x9A || 
		(c1 == 0xFF && (c2  == 0x2 || c2 == 0x3)))
			return 1;
	return 0;
}

static int is_ret_inst(unsigned int eip)
{
	unsigned char c1 = *(unsigned char *)eip;
	if (c1==0xc2 || c1==0xc3 || c1==0xcf)
		return 1;
	return 0;
}

static char *path2name(char *path)
{
	char *t = path + strlen(path);
	while (t>=path && *t!='/')
		t--;
	return t + 1;
}
