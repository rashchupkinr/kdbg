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
#include <asm/uaccess.h>
#include "include/kdbg.h"

extern volatile int status;
extern struct pt_regs *regs;
extern unsigned int esp0;
extern unsigned int cr3;
extern struct file *log_file;
extern struct break_struct *breakp;
extern char *ask_input;
extern so_t so[SYM_SO_N];

extern int print(char *, ...);
extern void dump(char *addr, int len);
extern int disasm(char *addr, char *buf);
extern unsigned int str2int(char *buf);
extern int is_sym(char c);
extern unsigned int mem_v2r(unsigned int vaddr);
extern unsigned int mem_can_read(unsigned int addr);
extern unsigned int mem_can_read_rgn(unsigned int addr, unsigned int len);
extern unsigned int *get_pesp();
extern unsigned int *get_pss();
extern strlist *strlist_find_val(strlist *, unsigned int);

static void parse(char *buf);

static int usr_run();
static int usr_dump_regs();
static int usr_dump();
static int usr_dump_raw();
static int usr_disasm();
static int usr_dump_sysregs();
static int usr_mem_writeb();
static int usr_mem_writel();
static int usr_mem_v2r();
static int usr_count();
static int usr_break_add();
static int usr_break_list();
static int usr_break_clear();
static int usr_break_disable();
static int usr_break_enable();
static int usr_hbreak_add();
static int usr_hbreak_clear();
static int usr_hbreak_disable();
static int usr_hbreak_enable();
static int usr_hbreak_list();
static int usr_step();
static int usr_next();
static int usr_go();
static int usr_ret();
static int usr_ncall();
static int usr_cur();
static int usr_vm();
static int usr_load_sym();
static int usr_log();
static int usr_help();

static char *argv[ARGC_MAX] = {0};
static int argc = 0;

struct command_struct {
	char *str;
	int (*handler) ();
	char *help;
};
static struct command_struct command[] = {
	{"run", usr_run, "run (F5):\nContinue execution"},
	{"reg", usr_dump_regs, "reg:\nShow/Set registers\nUsage:\nreg\nreg eip eip+2"},
	{"d", usr_dump, "d:\nDump data\nUsage:\nd addr len\nd esp\nd [esp+4] 5"},
	{"raw", usr_dump_raw, "d:\nDump raw data to log file\nraw addr len"},
	{"u", usr_disasm, "u:\nUnassemble\nu addr len\nu addr l8"},
	{"sysreg", usr_dump_sysregs, "sysreg:\nShow system registers"},
	{"2memb", usr_mem_writeb, "2memb:\nWrite byte to memory\nUsage:  2memb addr byte"},
	{"2meml", usr_mem_writel, "2meml:\nWrite long to memory\nUsage:  2meml addr long"},
	{"v2r", usr_mem_v2r, "v2r:\nTranslate virtual address to real\nUsage:  v2r vaddr"},
	{"bpx", usr_break_add, "bpx:\nSet breakpoint\nUsage:  bpx addr"},
	{"bl", usr_break_list, "bl:\nList breakpoints"},
	{"bc", usr_break_clear, "bc:\nClear breakpoint\nUsage:  bc break_num\nbc *"},
	{"bd", usr_break_disable, "bd:\nDisable breakpoint\nUsage:  bd break_num\nbd *"},
	{"be", usr_break_enable, "be:\nEnable breakpoint\nUsage:  be break_num\nbe *"},
	{"hbp", usr_hbreak_add, "hbp:\nSet hardware breakpoint\nUsage:  hbp addr [r rw x p] len"},
	{"hbc", usr_hbreak_clear, "hbc:\nSet hardware breakpoint\nUsage:  hbc hbreak_num"},
	{"hbd", usr_hbreak_disable, "hbd:\nDisable hardware breakpoint\nUsage:  hbd hbreak_num"},
	{"hbe", usr_hbreak_enable, "hbe:\nEnable hardware breakpoint\nUsage:  hbe hbreak_num"},
	{"hbl", usr_hbreak_list, "hbl:\nList hardware breakpoints"},
	{"n", usr_next, "n (F10):\nStep over call"},
	{"s", usr_step, "s (F8):\nStep one instruction"},
	{"g", usr_go, "g :\nGo to specified address\nUsage:  g 0xc1234567"},
	{"ret", usr_ret, "ret (F12):\nExit from function call"},
	{"ncall", usr_ncall, "n (F11):\nTrace to next call or ret"},
	{"cur", usr_cur, "cur:\nDump some process info"},
	{"vm", usr_vm, "vm:\nSet other vm by pid(decimal)\nUsage:  vm pid"},
	{"sym", usr_load_sym, "sym:\nLoad symbols from ELF file \nUsage:  sym /test 0x40000000"},
	{"log", usr_log, "log:\nSet log file\nExample:  log /path/logname\n log without args to stop logging"},
	{"?", usr_count, "?:\ncount expression\nExample:  ? 1c&12+1a"},
	{"help", usr_help, ""},
	{0, 0, 0}
};

static void exec()
{
	struct command_struct *com = command;
	if (!argc)
		return;
	while (com->str) {
		if (!strcmp(argv[0], com->str)) {
			if (com->handler()) {
				print(com->help);
				print("\n");
			}
			return;
		}
		com++;
	}
	argc = 0;
	print("Unknown command.\n");
}

static int usr_vm()
{
	if (argc == 2) {
		struct task_struct *proc;
		unsigned int pid = 0;
		dec2int(argv[1], &pid);
		for_each_task(proc)
			if (proc->pid == pid)
				break;
		if (proc == &init_task) {
			print("No task with pid %d\n", pid);
			return 0;
		}
		print("Switching address space to process %s\n", proc->comm);
//		set_cr3(proc->mm->pgd);
		print("This function is not working yet...\n");
		return 0;
	}
	return 1;
}

/*	
 *	Trace to next call or ret instruction
 *	return 1 if found call opcode, 0 otherwise
 */
static int usr_ncall()
{
	static int ncall_cnt = 0;

	if (ncall_cnt == 0x400) {
		ncall_cnt = 0;
		status &= ~STAT_NCALL;
		return 1;
	}

	if (is_call_inst(regs->eip)) {
		if (ncall_cnt == 0) {		// if already on call instruction
			status |= STAT_NCALL;
			ncall_cnt++;
			usr_next();
			return 0;
		}
		ncall_cnt = 0;
		status &= ~STAT_NCALL;
		return 1;
	} else if (is_ret_inst(regs->eip)) {
		print("Leaving current function\n");
		usr_step();
		ncall_cnt = 0;
		status &= ~STAT_NCALL;
		return 0;
	} else {
		ncall_cnt++;
		status |= STAT_NCALL;
		usr_next();
		return 0;
	}
}

static int usr_ret()
{
	static int ret_cnt = 0;

	ret_cnt++;
	if (ret_cnt == 0x400) {
		ret_cnt = 0;
		status &= ~STAT_RET;
		return;
	}
	
	if (is_ret_inst(regs->eip)) {		// ret or iret
		ret_cnt = 0;
		status &= ~STAT_RET;
		usr_step();
	} else {
		status |= STAT_RET;
		usr_next();
	}
	return 0;
}

static int usr_load_sym()
{
	int i;
	unsigned int base = 0;
	if (argc == 1) {
		print("Loaded symbols:\n");
		for (i=0;i<SYM_SO_N;i++)
			if (so[i].name[0])
				print("%s   %08lX\n", so[i].name, so[i].base);
		return 0;
	}
	if (argc == 3)
		base = str2int(argv[2]);

	schedule_sym_load(argv[1], base);
	return 0;
}

static int usr_next()
{
	char buf[64];
	int len;
	
	len = disasm((char *)regs->eip, buf);

	if (!strncmp(buf, "call", 4) || !strncmp(buf, "rep", 3)) {
		break_add(regs->eip + len, BREAK_TMP);
		usr_run();
	} else
		usr_step();
	return 0;
}

static int usr_step()
{
	regs->eflags |= X86_EFLAGS_TF;
	status |= STAT_TRACE | STAT_RUN;
	return 0;
}

static int usr_go()
{
	if (argc == 2) {
		break_add(str2int(argv[1]), BREAK_TMP);
		status |= STAT_RUN;
		return 0;
	}
	return 1;
}

static int usr_cur()
{
	print("current == %p\n", current);
	print("current->pid == %d\n", current->pid);
	print("current->comm == %s\n", current->comm);
	print("&current->comm == %p\n", &current->comm);
	print("current->mm == %p\n", current->mm);
	print("current->thread == %p\n", current->thread);
	print("current->fs == %p\n", current->fs);
	print("current->files == %p\n", current->files);
	return 0;
}

static int usr_log()
{
	if (argc == 2) {
		log_file = filp_open(argv[1], O_ACCMODE | O_CREAT | O_APPEND, O_RDWR);
		if (IS_ERR(log_file)) {
			log_file = 0;
			print("Error opening file %s\n", argv[1]);
		}
		return 0;
	}
	if (log_file) {
		filp_close(log_file, current->files);
		log_file = 0;
		return 0;
	}
	return 1;
}

static int usr_hbreak_add()
{
	unsigned int attr = 0;
	if (argc != 4)
		return 1;
	if (argv[2]) {
		if (strstr(argv[2], "rw"))
			attr |= HBREAK_RDWR;
		else if (strstr(argv[2], "w"))
			attr |= HBREAK_WRITE;
		else if (strstr(argv[2], "x"))
			attr |= HBREAK_EXEC;
		else if (strstr(argv[2], "p"))
			attr |= HBREAK_PORT;
	}
	hbreak_add(str2int(argv[1]), attr, str2int(argv[3]));
	return 0;
}

static int usr_hbreak_clear()
{
	if (argc = 2) {
		if (argv[1][0] == '*') {
			hbreak_clear(0);	hbreak_clear(1);
			hbreak_clear(2);	hbreak_clear(3);
			return 0;
		}
		hbreak_clear(str2int(argv[1]));
		return 0;
	}
	return 1;
}

static int usr_hbreak_disable()
{
	if (argc == 2) {
		if (*argv[1] == '*') {
			hbreak_disable(0);	hbreak_disable(1);
			hbreak_disable(2);	hbreak_disable(3);
		} else
			hbreak_disable(str2int(argv[1]));
		return 0;
	}
	return 1;
}

static int usr_hbreak_enable()
{
	if (argc == 2) {
		if (*argv[1] == '*') {
			hbreak_enable(0);	hbreak_enable(1);
			hbreak_enable(2);	hbreak_enable(3);
		} else
			hbreak_enable(str2int(argv[1]));
		return 0;
	}
	return 1;
}

static int usr_hbreak_list()
{
	hbreak_list();
	return 0;
}

static int usr_break_add()
{
	if (argc == 2) {
		break_add(str2int(argv[1]), 0, 0);
		return 0;
	}
	return 1;
}

static int usr_break_disable()
{
	if (argc == 2) {
		if (*argv[1] == '*') {
			int i;
			for (i = 0; i < BREAK_MAX; i++)
				if (breakp[i].addr)
					breakp[i].attr |= BREAK_DISABLED;
		} else {
			int n = str2int(argv[1]);
			if (breakp[n].addr)
				breakp[n].attr |= BREAK_DISABLED;
		}
		return 0;
	}
	return 1;
}

static int usr_break_enable()
{
	if (argc == 2) {
		if (*argv[1] == '*') {
			int i;
			for (i = 0; i < BREAK_MAX; i++)
				if (breakp[i].addr)
					breakp[i].attr &= ~BREAK_DISABLED;
		} else {
			int n = str2int(argv[1]);
			if (breakp[n].addr)
				breakp[n].attr &= ~BREAK_DISABLED;
		}
		return 0;
	}
	return 1;
}

static int usr_break_list()
{
	break_list();
	return 0;
}

static int usr_break_clear()
{
	if (argc == 2) {
		if (*argv[1] == '*') {
			int i;
			for (i = 0; i < BREAK_MAX; i++)
				break_clear(i);
			return 0;
		} else
			break_clear(str2int(argv[1]));
		return 0;
	}
	return 1;
}

static int usr_mem_writeb()
{
	if (argc == 3) {
		mem_writeb(str2int(argv[1]), str2int(argv[2]));
		return 0;
	}
	return 1;
}

static int usr_mem_writel()
{
	if (argc == 3) {
		mem_writel(str2int(argv[1]), str2int(argv[2]));
		return 0;
	}
	return 1;
}

static int usr_mem_v2r()
{
	if (argc == 2) {
		unsigned int raddr = mem_v2r(str2int(argv[1]));
		print("%08lX -> %08lX -> %08lX\n", str2int(argv[1]), raddr,
		      __va(raddr));
		return 0;
	}
	return 1;
}

static int usr_run()
{
	if (argc == 2) {
		break_add(str2int(argv[1]), BREAK_TMP);
	}
	status |= STAT_RUN;
	status &= ~STAT_TRACE;
	regs->eflags &= ~X86_EFLAGS_TF;
	return 0;
}

static int usr_count()
{
	if (argc == 2) {
		print("%X\n", str2int(argv[1]));
		return 0;
	}
	return 1;
}

static int usr_disasm()
{
	char buf[80];
	char buf1[128];
	char *cur_buf;
	unsigned int len = 0;
	unsigned int lines = 0;
	unsigned char *addr, *_addr;
	int inst_size, i;

	lines = 0x12;
	len = lines * 10;
	if (argc == 1) {
		addr = (unsigned char *) regs->eip;
	} else {
		addr = (unsigned char *) str2int(argv[1]);
		if (argc == 3)
			if (*argv[2] == 'l') {
				lines = str2int(argv[2] + 1);
				len = lines * 10;
			} else {
				len = str2int(argv[2]);
				lines = len * 10;
			}
	}

	if (!mem_can_read_rgn((unsigned int) addr, len))
		return;
	_addr = addr + len;
	while ((addr <= _addr) && lines--) {

		if (sym_find_by_val(addr, buf1)) {
			print("%s:\n", buf1);
			lines--;
		}

		memset((void *) buf, ' ', 80);
		sprintf((char *) buf, "%08lX | ", addr);
		sprintf((char *) buf + 34, "|");

		inst_size = disasm(addr, buf + 38);
		cur_buf = buf + 11;
		for (i = 0; i < inst_size; i++)
			cur_buf += sprintf((char *) cur_buf, "%02lX", addr[i]);

		for (i = 0; i < 80; i++)
			print("%c", buf[i]);
		print("\n");

		addr += inst_size;
	}
	return 0;
}

static int usr_dump()
{
	unsigned char *addr;
	int len;
	if (argc == 1)
		return 1;
	addr = (unsigned char *)str2int(argv[1]);
	if (argc == 2)
		len = 0x80;
	else 
		len = str2int(argv[2]);
	dump(addr, len);
	return 0;
}

static int usr_dump_raw()
{
	mm_segment_t old_fs;
	int len;
	unsigned char *addr = (unsigned char *) str2int(argv[1]);

	if (argc == 1)
		return 1;
	if (argc == 3)
		len = str2int(argv[2]);
	else
		len = 0x80;

	if (!mem_can_read_rgn((unsigned int) addr, len))
		return;

	if (!log_file) {
		print("Error: log file unspecified\n");
		return 1;
	}
	old_fs = get_fs();
	set_fs(get_ds());
	log_file->f_op->write(log_file, addr, len, &log_file->f_pos);
	set_fs(old_fs);

	print("\n");
	return 0;
}

static void parse(char *buf)
{
	argc = 0;
	while ((*buf) && (argc < ARGC_MAX)) {
		while (*buf == ' ')
			buf++;
		if (argc)
			*(buf - 1) = 0;
		argv[argc++] = buf;
		while (*buf != ' ' && *buf)
			buf++;
	}
}

static int usr_dump_sysregs()
{
	unsigned char descr[6] = { 0 };
	unsigned short task_reg;
	unsigned int cr0, cr2, cr3, cr4;
	unsigned int dr0, dr1, dr2, dr3, dr4, dr6, dr7;
	__asm__ volatile ("sgdt	%0":"=m" (descr));
	print("gdtr: %02lX%02lX%02lX%02lX%02lX%02lX   ",
	     descr[0], descr[1], descr[2], descr[3], descr[4], descr[5]);
	__asm__ volatile ("sldt	%0":"=m" (descr));
	print("ldtr: %02lX%02lX%02lX%02lX%02lX%02lX   ", descr[0],
	      descr[1], descr[2], descr[3], descr[4], descr[5]);
	__asm__ volatile ("sidt	%0":"=m" (descr));
	print("idtr: %02lX%02lX%02lX%02lX%02lX%02lX   ", descr[0],
	      descr[1], descr[2], descr[3], descr[4], descr[5]);
	__asm__ volatile ("\nstr %0":"=m" (task_reg));
	print("task_reg: %04lX   ", task_reg);
	get_cr0(cr0);	get_cr2(cr2);
	get_cr3(cr3);	get_cr4(cr4);
	print("cr0: %08lX   cr2: %08lX   cr3: %08lX   cr4: %08lX\n",
	     cr0, cr2, cr3, cr4);
	get_dr0(dr0);	get_dr1(dr1);	get_dr2(dr2);
	get_dr3(dr3);	get_dr6(dr6);	get_dr7(dr7);
	print("dr0: %08lX   dr1: %08lX   dr2: %08lX   dr3: %08lX\ndr6: %08lX   dr7: %08lX\n",
	     dr0, dr1, dr2, dr3, dr6, dr7);
	return 0;
}

static int usr_help()
{
	struct command_struct *com = command;
	if (argc == 1) {
		print("Available commands:\n");
		while (com->str) {
			print("%s    ", com++->str);
			if ((com - command) % 8 == 0)
				print("\n");
		}
	} else {
		while (com->str) {
			if (!strcmp(com->str, argv[1])) {
				print("%s\n", com->help);
				return 0;
			}
			com++;
		}
		print("Unknown command %s\n Use help withaout args",
		      argv[1]);}
	print("\n");
	return 0;
}

static int usr_dump_regs()
{
	unsigned int *pesp = (unsigned int *)get_pesp();
	unsigned int *pss = (unsigned int *)get_pss();
	unsigned int fs;
	if (argc == 3) {
		unsigned int tmp = str2int(argv[2]);
		argc = 0;
		if (strcmp(argv[1], "eip") == 0) { regs->eip = tmp; return 0; }
		if (strcmp(argv[1], "eax") == 0) { regs->eax = tmp; return 0; }
		if (strcmp(argv[1], "edx") == 0) { regs->edx = tmp; return 0; }
		if (strcmp(argv[1], "ecx") == 0) { regs->ecx = tmp; return 0; }
		if (strcmp(argv[1], "ebx") == 0) { regs->ebx = tmp; return 0; }
		if (strcmp(argv[1], "esi") == 0) { regs->esi = tmp; return 0; }
		if (strcmp(argv[1], "edi") == 0) { regs->edi = tmp; return 0; }
		if (strcmp(argv[1], "ebp") == 0) { regs->ebp = tmp; return 0; }
		if (strcmp(argv[1], "cs" ) == 0) { regs->xcs = tmp; return 0; }
		if (strcmp(argv[1], "ds" ) == 0) { regs->xds = tmp; return 0; }
		if (strcmp(argv[1], "es" ) == 0) { regs->xes = tmp; return 0; }
		if (strcmp(argv[1], "dr0") == 0) { set_dr0(tmp); return 0; }
		if (strcmp(argv[1], "dr1") == 0) { set_dr1(tmp); return 0; }
		if (strcmp(argv[1], "dr2") == 0) { set_dr2(tmp); return 0; }
		if (strcmp(argv[1], "dr3") == 0) { set_dr3(tmp); return 0; }
		if (strcmp(argv[1], "dr6") == 0) { set_dr6(tmp); return 0; }
		if (strcmp(argv[1], "dr7") == 0) { set_dr7(tmp); return 0; }
		if (strcmp(argv[1], "cr0") == 0) { set_cr0(tmp); return 0; }
		if (strcmp(argv[1], "cr2") == 0) { set_cr2(tmp); return 0; }
		if (strcmp(argv[1], "cr3") == 0) { set_cr3(tmp); return 0; }
		if (strcmp(argv[1], "cr4") == 0) { set_cr4(tmp); return 0; }
		if (strcmp(argv[1], "eflags") == 0) { regs->eflags = tmp; return 0; }
		if (strcmp(argv[1], "esp") == 0) { 
			if (regs->eip >= __PAGE_OFFSET) {
				print("Can't change esp in kernel\n");
				return 0;
			}
			*pesp = tmp;
			return 0;
		}
		return 1;
	}
	__asm__("movl %%fs, %0\n":"=r" (fs));
	print("eip: %08lX   eflags: %08lX\n",
	     regs->eip, regs->eflags);
	print("eax: %08lX   ebx: %08lX   ecx: %08lX   edx: %08lX\n",
	     regs->eax, regs->ebx, regs->ecx, regs->edx);
	print("esi: %08lX   edi: %08lX   ebp: %08lX   esp: %08lX\n",
	     regs->esi, regs->edi, regs->ebp, *pesp);
	print("cs: %04X   ds: %04X   es: %04X   fs: %04X   ss: %04X\n",
	     0xffff & regs->xcs, regs->xds & 0xffff,
	     regs->xes & 0xffff, fs, *pss);
	return 0;
}
