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

extern unsigned int mem_v2r(unsigned int vaddr);

static struct hbreak_struct hbreakp[4] =
    { {0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0} };

static int hbreak_add(unsigned int addr, unsigned int attr,
		      unsigned int len);
static int hbreak_clear(int n);
static void hbreak_list();
static void hbreak_disable(int n);
static void hbreak_enable(int n);

static int hbreak_add(unsigned int addr, unsigned int attr,
		      unsigned int len)
{
	unsigned int dr7;
	int i = 0;
	while ((i < 4) && (hbreakp[i].addr != 0))
		i++;
	if (i == 4) {
		print("Can't set hard breakpoint - 4 max\n");
		return -1;
	}
	switch (i) {
	case 0:	set_dr0(addr);	break;
	case 1:	set_dr1(addr);	break;
	case 2:	set_dr2(addr);	break;
	case 3:	set_dr3(addr);	break;
	}
	get_dr7(dr7);
	dr7 |= 0x00000200;
	dr7 &= ~(0x000F000F << i * 2);
	if (attr & HBREAK_EXEC) {
	} else if (attr & HBREAK_WRITE) {
		dr7 |= 0x00010000 << i * 2;
	} else if (attr & HBREAK_RDWR) {
		dr7 |= 0x00030000 << i * 2;
	} else if (attr & HBREAK_PORT) {
		dr7 |= 0x00020000 << i * 2;
	}
	switch (len) {
	case 1:					break;
	case 2:	dr7 |= 1 << (18 + i * 2);	break;
	case 4:	dr7 |= 3 << (18 + i * 2);	break;
	default:
		print("Error setting hard breakpoint: len must be 1, 2 or 4\n");
		return -1;
	}
	dr7 |= 3 << i * 2;
	set_dr7(dr7);
	current->thread.debugreg[7] = dr7;
	current->thread.debugreg[0] = addr;
	hbreakp[i].addr = addr;
	hbreakp[i].attr = attr;
	hbreakp[i].len = len;
	return 0;
}

static void hbreak_disable(int n)
{
	unsigned int dr7;
	get_dr7(dr7);
	dr7 &= ~(0x00000002 << (n * 2));
	set_dr7(dr7);
	hbreakp[n].attr |= BREAK_DISABLED;
}

static void hbreak_enable(int n)
{
	unsigned int dr7;
	get_dr7(dr7);
	dr7 |= 0x00000002 << (n * 2);
	set_dr7(dr7);
	hbreakp[n].attr &= ~BREAK_DISABLED;
}

static int hbreak_clear(int n)
{
	unsigned int dr7;
	hbreakp[n].addr = 0;
	hbreakp[n].attr = 0;
	hbreakp[n].len = 0;
	get_dr7(dr7);
	dr7 &= ~(0x00000002 << (n * 2));
	set_dr7(dr7);
}

static void hbreak_list()
{
	int i;
	for (i = 0; i < 4; i++)
		if (hbreakp[i].addr) {
			print("%d) %08lX ", i, hbreakp[i].addr);
			if (hbreakp[i].attr & HBREAK_WRITE)
				print("w");
			else if (hbreakp[i].attr & HBREAK_RDWR)
				print("rw");
			else if (hbreakp[i].attr & HBREAK_EXEC)
				print("x");
			else if (hbreakp[i].attr & HBREAK_PORT)
				print("p");
			if (hbreakp[i].attr & BREAK_DISABLED)
				print(" * ");
			print("\n");
		}
}
