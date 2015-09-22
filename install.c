#define	MODULE
#define	__KERNEL__
#define	__KERNEL_SYSCALLS__
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sys.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include "include/kdbg.h"
#include <linux/fs.h>
#include <asm/uaccess.h>

extern void int3();
extern void int1();
extern void irq1();
extern strlist *strlist_init();
extern void strlist_clean();
extern void sym_load_modules();

extern struct file *log_file;
extern struct break_struct *breakp;
extern strlist *ihist;

int init_module()
{
	break_init();
	ihist = strlist_init();
	sym_load("/boot/vmlinux", 0);
	sym_load("/lib/ld-linux.so.2", 0x40000000);
//	sym_so_load("/lib/libc.so.6",-1);
	int_install(3, __KERNEL_CS, (void *) int3);
	int_install(1, __KERNEL_CS, (void *) int1);
	int_install(0x21, __KERNEL_CS, (void *) irq1);

	return 0;
}

void cleanup_module()
{
	int_uninstall(0x21);
	int_uninstall(1);
	int_uninstall(3);

	sym_clean();
	break_clean();
	hbreak_clear(0);	hbreak_clear(1);
	hbreak_clear(2);	hbreak_clear(3);
	strlist_clean(ihist);
	if (log_file)
		filp_close(log_file, current->files);
}
