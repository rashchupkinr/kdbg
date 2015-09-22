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
#include <linux/ioport.h>
#include "include/kdbg.h"

extern void irq1();
extern void hide_breakps();
extern void refresh_breakps();
extern int break_find(unsigned int addr);
extern struct break_struct *breakp;
extern char *ask_input;

static volatile int status = 0;
static unsigned int esp0;
static unsigned int ss0;
static unsigned int cr3;
static struct pt_regs *regs;

static char *separate_line =
    "\n##################################### KDBG #####################################\n";
static void print_int3_invite();


static asmlinkage int do_int3()			// return 1 if handled
{
	unsigned int dr6;
	int break_num;
	int i;

	regs->eip--;

	break_num = break_find(regs->eip);
	if (break_num == -1 && !(status & STAT_TRACE) && !(status & STAT_IRQ1) && 
						regs->eip < PAGE_OFFSET) {
		regs->eip++;
		print("KDBG:   skipping INT 3:   task == %s    pid == %d    eip == %p\n",
				current->comm, current->pid, regs->eip);
		return 0;
	}
	
	if ((status & STAT_IRQ1) == 0) {	// not by Ctrl+Alt+D

		break_clear_tmp();

		if (status & STAT_RET) {
			usr_ret();
			break_refresh_all();
			return 1;
		}
		
		if (status & STAT_NCALL) {
			if (!usr_ncall())
				return 1;
			break_refresh_all();
		}
//		if ((status & STAT_TRACE) == 0)
//			if (break_num == -1) {	}
	} else
		regs->eip++;

	break_hide_all();

	print_int3_invite();
	status &= ~STAT_TRACE & ~STAT_IRQ1;
	status |= STAT_INT3;

	get_cr3(cr3);
	status &= ~STAT_RUN;


	while ((status & STAT_RUN) == 0) {}


	set_cr3(cr3);
	status &= ~(STAT_RUN | STAT_INT3);

	if ((status & STAT_TRACE) == 0)
		print(separate_line);

	break_refresh_all();

	if (break_num != -1) {				// to not break again
		mem_writeb(breakp[break_num].addr,
				   breakp[break_num].old_byte);
		regs->eflags |= X86_EFLAGS_TF;	// do_int1() will call break_refresh_all()
	}

	dr6 = 0xFFFF0FF0;
	set_dr6(dr6);

	current->need_resched = 0;
	return 1;
}


static int __asm_tmp;
__asm__ (
"int3:"
	"movl	%esp, esp0\n"
	"addl	$0xc, esp0\n"
	"pushw	%ss\n"
	"popw	ss0\n"

	"pushl	$3-0xff\n"
	"pushl	%es\n"
	"pushl	%ds\n"
	"pushl	%eax\n"
	"pushl	%ebp\n"
	"pushl	%edi\n"
	"pushl	%esi\n"
	"pushl	%edx\n"
	"pushl	%ecx\n"
	"pushl	%ebx\n"
	"movl	%esp, regs\n"

	"movl	$0x18, %eax\n"
	"movl	%eax, %ds\n" 
	"movl	%eax, %es\n"
	"movl	%eax, %ss\n"

	"sti\n"
	"mov	$0x20, %al\n"
	"outb	%al, $0x20\n"
	"outb	%al, $0xA0\n"

	"inb	$0x21, %al\n"		// Disable all IRQs except
	"orb	$0xfd, %al\n"		// one from keyboard
	"outb	%al, $0x21\n"
	"inb	$0xa1, %al\n"
	"orb	$0xff, %al\n"
	"outb	%al, $0xa1\n"

	"call	do_int3\n"
	"testl	%eax, %eax\n"
	"jz	int3_not_handled\n"

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

"int3_not_handled:"
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

	"movl	%eax, __asm_tmp\n"
	"pushl	$3\n"
	"call	int_get_old\n"
	"movl	%eax, (%esp)\n"
	"movl	__asm_tmp, %eax\n"
	"retl\n"
);


static void print_int3_invite()
{
	char buf[64] = {0};
	if ((status & STAT_TRACE) == 0) {
		print(separate_line);
		print("current:  %08lX     pid: %d     comm: %s\n",
			current, current->pid, current->comm);
	} else
		print("\n");

	usr_dump_regs();

	sym_find_by_val(regs->eip, buf);
	if (buf[0])
		print("%s:\n", buf);
	disasm(regs->eip, buf);
	print("%08lX | %s\n", regs->eip, buf);
	print(ask_input);
}
