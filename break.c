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

extern int print(char *, ...);
extern volatile int status;
static struct break_struct *breakp;

static int break_add(unsigned int addr, int attr)
{
	int i;
	for (i = 0; (i < BREAK_MAX) && (breakp[i].addr); i++)
		if (breakp[i].addr == addr) {
			print("Break: duplicate breakpoint\n");
			return 1;
		}
	if (i == BREAK_MAX) {
		print("Break: No more free breakpoints\n");
		return 1;
	}
	if (!mem_can_read(addr)) {
		print("Break: Virtual memory %08lX is unavailable\n", addr);
		return 1;
	}
	breakp[i].addr = addr;
	breakp[i].old_byte = *(unsigned char *) addr;
	breakp[i].attr = attr;
	return 0;
}

static void break_clear(unsigned int n)
{
	if (n >= 0 && n < BREAK_MAX)
		if (breakp[n].addr) {
			mem_writeb(breakp[n].addr, breakp[n].old_byte);
			memset(&breakp[n], 0, sizeof(struct break_struct));
		}
}

static void break_clear_tmp()
{
	int i;
	for (i = 0; i < BREAK_MAX; i++)
		if (breakp[i].attr & BREAK_TMP)
			break_clear(i);
}

static void break_list()
{
	int i;
	for (i = 0; i < BREAK_MAX; i++)
		if (breakp[i].addr) {
			print("%02lX) %08lX", i, breakp[i].addr);
			if (breakp[i].attr & BREAK_DISABLED)
				print(" *");
			print("\n");
		}
}

static int break_find(unsigned int addr)
{
	int i;
	for (i = 0; i < BREAK_MAX; i++)
		if (breakp[i].addr == addr)
			return i;
	return -1;
}

static void break_init()
{
	breakp = (struct break_struct *)
	    kmalloc(BREAK_MAX * sizeof(struct break_struct), GFP_ATOMIC);
	memset(breakp, 0, BREAK_MAX * sizeof(struct break_struct));
}

static void break_hide_all()
{
	int i;
	for (i = 0; i < BREAK_MAX; i++)
//		if ((breakp[i].attr & BREAK_DISABLED) == 0)
			if (breakp[i].addr)
				mem_writeb(breakp[i].addr, breakp[i].old_byte);
}

static void break_refresh_all()
{
	int i;
	for (i = 0; i < BREAK_MAX; i++) {
		if ((breakp[i].attr & BREAK_DISABLED) == 0)
			if (breakp[i].addr)
				mem_writeb(breakp[i].addr, 0xCC);
	}
}

static void break_clean()
{
	int i;
	for (i = 0; i < BREAK_MAX; i++)
		break_clear(i);
	kfree(breakp);
}
