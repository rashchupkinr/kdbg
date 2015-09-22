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

extern volatile int status;

static struct int_struct *interrupt = 0;

static char *get_idt()
{
	char idt_descr[6] = { 0 };
	__asm__ volatile ("sidt	%0":"=m" (idt_descr));
	return (char *) *(int *) &idt_descr[2];
}

static void int_install(int n, short sel, void (*new_int) ())
{
	unsigned char *idt;
	struct int_struct *cur_int;

	if (interrupt) {
		cur_int = interrupt;
		while (cur_int->next) {
			if (cur_int->num == n)
				return;
			cur_int = cur_int->next;
		}
		cur_int = cur_int->next =
		    (void *) kmalloc(sizeof(struct int_struct), GFP_ATOMIC);
	} else
		cur_int = interrupt =
		    (void *) kmalloc(sizeof(struct int_struct), GFP_ATOMIC);
	cur_int->next = 0;
	cur_int->num = n;

	idt = get_idt();

	cur_int->old_sel = (short) idt[8 * n + 2];
	((char *) &cur_int->old_int)[0] = idt[8 * n + 0];
	((char *) &cur_int->old_int)[1] = idt[8 * n + 1];
	((char *) &cur_int->old_int)[2] = idt[8 * n + 6];
	((char *) &cur_int->old_int)[3] = idt[8 * n + 7];

	mem_writeb(&idt[8*n+2], ((char *) &sel)[0]);
	mem_writeb(&idt[8*n+3], ((char *) &sel)[1]);

	mem_writeb(&idt[8*n+0], ((char *) &new_int)[0]);
	mem_writeb(&idt[8*n+1], ((char *) &new_int)[1]);
	mem_writeb(&idt[8*n+6], ((char *) &new_int)[2]);
	mem_writeb(&idt[8*n+7], ((char *) &new_int)[3]);
}

static void int_uninstall(int n)
{
	struct int_struct *cur_int, *prev_int;
	if (!interrupt)
		return;
	prev_int = 0;
	cur_int = interrupt;
	while (cur_int) {
		if (cur_int->num == n) {
			unsigned char *idt = get_idt();
		
			mem_writeb(&idt[8*n+2], ((char *) &cur_int->old_sel)[0]);
			mem_writeb(&idt[8*n+3], ((char *) &cur_int->old_sel)[1]);

			mem_writeb(&idt[8*n+0], ((char *) &cur_int->old_int)[0]);
			mem_writeb(&idt[8*n+1], ((char *) &cur_int->old_int)[1]);
			mem_writeb(&idt[8*n+6], ((char *) &cur_int->old_int)[2]);
			mem_writeb(&idt[8*n+7], ((char *) &cur_int->old_int)[3]);
			kfree(cur_int);
			if (cur_int == interrupt)
				interrupt = 0;
			else
				prev_int->next = 0;
			return;
		}
		prev_int = cur_int;
		cur_int = cur_int->next;
	}
	return;
}

static asmlinkage struct int_struct *int_get(int n)
{
	struct int_struct *cur_int = interrupt;
	while (cur_int) {
		if (cur_int->num == n)
			return cur_int;
		cur_int = cur_int->next;
	}
}

static asmlinkage unsigned int int_get_old(int n)
{
	struct int_struct *i = int_get(n);
	if (!i)
		return 0;
	return i->old_int;
}
