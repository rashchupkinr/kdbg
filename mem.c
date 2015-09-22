#define	MODULE
#define	__KERNEL__
#define	__KERNEL_SYSCALLS__
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sys.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <asm/pgtable.h>
#include <asm/uaccess.h>
#include "include/kdbg.h"

extern volatile int status;

static unsigned int *mem_get_pde(unsigned int addr);
static int mem_writeb(unsigned int addr, unsigned char c);
static int mem_writel(unsigned int addr, unsigned int l);
static int mem_can_read(unsigned int addr);
static unsigned int *mem_get_page(unsigned int addr);
static int mem_addr_valid(unsigned int addr);
static unsigned int mem_v2r(unsigned int vaddr);
static unsigned int mem_can_read_rgn(unsigned int addr, unsigned int len);

static unsigned int mem_v2r(unsigned int vaddr)
{
	unsigned int *pde, *pte;
	unsigned int cr4;
	unsigned int raddr;
	
	pde = mem_get_pde(vaddr);
	if (!*pde)
		return 0;
	get_cr4(cr4);
	if ((cr4 & X86_CR4_PSE) && (*pde & _PAGE_PSE)) {
		raddr = (*pde & 0xFFC00000) | (vaddr & 0x003FFFFF);
	} else {
		pte = (unsigned int *) (__va(*pde & 0xfffff000) +
					4 * ((vaddr & 0x003ff000) >> 12));
		if (!*pte)
			return 0;
		raddr = (*pte & 0xfffff000) | (vaddr & 0x00000FFF);
	}
	return raddr;
}

static int mem_addr_valid(unsigned int addr)
{
	if ((addr < PAGE_OFFSET) || (addr >= __pa(high_memory)))
		return 0;
	return 1;
}

static unsigned int *mem_get_pde(unsigned int addr)
{
	unsigned int *cr3;
	get_cr3(cr3);
	return (unsigned int *) (__va(cr3) + 4 * (addr >> 22));
}

static unsigned int *mem_get_page(unsigned int addr)
{
	unsigned int *pde, *pte;
	unsigned int cr4;
	
	pde = mem_get_pde(addr);
	if (!*pde)
		return 0;
	get_cr4(cr4);
	if ((cr4 & X86_CR4_PSE) && (*pde & _PAGE_PSE))
		return pde;
	pte = (unsigned int *) (__va(*pde & 0xfffff000) +
				4 * ((addr & 0x003ff000) >> 12));
	if (!*pte)
		return 0;
	return pte;
}

static int mem_can_read(unsigned int addr)
{
	unsigned int *pte = mem_get_page(addr);
	if (!pte)
		return 0;
	if (*pte & _PAGE_PRESENT)
		return 1;
	return 0;
}

static int mem_writeb(unsigned int addr, unsigned char c)
{
	unsigned int *pte = (unsigned int *) mem_get_page(addr);
	
	if (!pte)
		return 0;
	if (*pte & _PAGE_PRESENT) {
		if (*pte & _PAGE_RW)
			*(unsigned char *) addr = c;
		else {
			*pte |= _PAGE_RW;
			*(unsigned char *) addr = c;
			*pte &= ~_PAGE_RW;
		}

		return 1;
	}

/*	if (addr >= PAGE_OFFSET)
		*(unsigned char *)addr = c;
	else
		put_user(c, (unsigned char *)addr);
*/	return 0;
}

static int mem_writel(unsigned int addr, unsigned int l)
{
	int i;
	int retval = 1;
	for (i = 0; i < 4; i++)
		retval &= mem_writeb(addr++, *((unsigned char *) &l + i));
	return retval;
}

static unsigned int mem_can_read_rgn(unsigned int addr, unsigned int len)
{
	if ((!mem_can_read(addr)) || (!mem_can_read(addr + len))) {
		print("Virtual memory [%08lX; %08lX] is unavailable\n",
		      addr, addr + len);
		return 0;
	}
	return 1;
}
