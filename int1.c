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
#include <asm/processor.h>
#include "include/kdbg.h"

extern void break_refresh_all();

extern volatile int status;
extern unsigned int esp0;
extern unsigned int pss0;
extern struct pt_regs *regs;

static asmlinkage int do_int1()
{
	unsigned int dr6;
	int ret = 1;

	get_dr6(dr6);
	break_refresh_all();
	
	if ((dr6 & X86_DR6_B0) || (dr6 & X86_DR6_B1) ||		// dr0 - dr3
	    (dr6 & X86_DR6_B2) || (dr6 & X86_DR6_B3)) {
		regs->eip++;
		ret = do_int3();
		regs->eflags |= X86_EFLAGS_RF;
	} else if ((dr6 & X86_DR6_BS) && (status & STAT_TRACE)) { // Tracing
		regs->eflags &= ~X86_EFLAGS_TF;
		regs->eip++;
		ret = do_int3();
	}

	dr6 = 0xFFFF0FF0;
	set_dr6(dr6);
	return ret;
}

static int __asm_tmp2;
__asm__("int1:\n"
	"movl	%esp, esp0\n"
	"addl	$0xc, esp0\n"
	"pushw	%ss\n"
	"popw	ss0\n"
	
	"pushl	$3-256\n"
	"pushl	%es\n"
	"pushl	%ds\n"
	"pushl	%eax\n"
	"pushl	%ebp\n"
	"pushl	%edi\n"
	"pushl	%esi\n"
	"pushl	%edx\n"
	"pushl	%ecx\n"
	"pushl	%ebx\n"
	"movl	$0x18, %eax\n"
	"movl	%eax, %ds\n"
	"movl	%eax, %es\n"
	"movl	%eax, %ss\n"
	"movl	%esp, regs\n"

	"sti\n"
	"mov	$0x20, %al\n"
	"outb	%al, $0x20\n"
	"outb	%al, $0xA0\n"

	"inb	$0x21, %al\n"
	"orb	$0xfd, %al\n"
	"outb	%al, $0x21\n"
	"inb	$0xa1, %al\n"
	"orb	$0xff, %al\n"
	"outb	%al, $0xa1\n"

	"call	do_int1\n"
	"testl	%eax, %eax\n"
	"jz	int1_not_handled\n"

	"inb	$0x21, %al\n"		// Enable all IRQs
	"andb	$0x02, %al\n"
	"outb	%al, $0x21\n"
	"inb	$0xa1, %al\n"
	"andb	$0x00, %al\n"
	"outb	%al, $0xa1\n"

	"popl	%ebx\n"
	"popl	%ecx\n"
	"popl	%edx\n"
	"popl	%esi\n"
	"popl	%edi\n"
	"popl	%ebp\n"
	"popl	%eax\n"
	"popl	%ds\n"
	"popl	%es\n"
	"addl	$4, %esp\n"
	"iretl\n"

"int1_not_handled:\n"
	"inb	$0x21, %al\n"
	"andb	$0x02, %al\n"
	"outb	%al, $0x21\n"

	"popl	%ebx\n"
	"popl	%ecx\n"
	"popl	%edx\n"
	"popl	%esi\n"
	"popl	%edi\n"
	"popl	%ebp\n"
	"popl	%eax\n"
	"popl	%ds\n"
	"popl	%es\n"
	"addl	$4, %esp\n"
	"movl	%eax, __asm_tmp2\n"
	"pushl	$1\n"
	"call	int_get_old\n"
	"movl	%eax, (%esp)\n"
	"movl	__asm_tmp2, %eax\n"
	"retl\n"
	);
