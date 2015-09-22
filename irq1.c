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
#include <linux/pc_keyb.h>
#include "include/kdbg.h"
#include "include/keymap.h"

extern struct tasklet_struct keyboard_tasklet;

extern volatile int status;
extern unsigned int argc;

extern int print(char *, ...);
extern void strlist_add(strlist *, char *input, unsigned int val);
extern strlist *strlist_end(strlist *);

static void irq1();
static void irq1_init_kbd_state();

static unsigned char scancode;
static unsigned char kbd_status;

#define	SHIFT_STATE	0x1
#define	CTRL_STATE	0x2
#define	ALTGR_STATE	0x4
static char kbd_state;

static char *ask_input = "> ";
static strlist *ihist;
static strlist *ihist_cur;

static void irq1_orig(unsigned char scancode);
static void irq1_new(unsigned char scancode);


static void do_irq1(void)
{
	irq1_init_kbd_state();
	if ((status & STAT_INT3) == 0) {
		if ((kbd_state & CTRL_STATE) && (kbd_state & ALTGR_STATE)
			&& (scancode == 0x20)) {	// Ctrl+Alt+D
			status |= STAT_IRQ1;
			__asm__("int $3\ncli\n");
			irq1_orig(0x1D | 0x80);		// Release Ctrl
			irq1_orig(0x38 | 0x80);		// Release Alt
			return;
		}
		irq1_orig(scancode);
		return;
	}
	irq1_new(scancode);
	return;
}

static void irq1_init_kbd_state()
{
	if (~scancode & 0x80) {			// key_down
		switch (scancode) {
		case 0x2A:
		case 0x3A:	kbd_state |= SHIFT_STATE;	break;
		case 0x1D:	kbd_state |= CTRL_STATE;	break;
		case 0x38:	kbd_state |= ALTGR_STATE;	break;
		}
	} else {
		if ((kbd_state & SHIFT_STATE)
		    && (scancode == 0x2A + 0x80 || scancode == 0x3A + 0x80))
			 kbd_state &= ~SHIFT_STATE;
		else if ((kbd_state & ALTGR_STATE) && scancode == 0x38 + 0x80)
			 kbd_state &= ~ALTGR_STATE;
		else if ((kbd_state & CTRL_STATE) && scancode == 0x1D + 0x80)
			 kbd_state &= ~CTRL_STATE;
	}
}

static void irq1_orig(unsigned char scancode)
{
	handle_scancode(scancode, !(scancode & 0x80));
	tasklet_schedule(&keyboard_tasklet);
}

static void irq1_new(unsigned char scancode)
{
	static char kbuf[KBUF_SIZE];
	static unsigned int kpos = 0;
	switch (scancode) {
	case 0xC8:{		// Arrow_UP
			if (!ihist_cur || !ihist_cur->prev)
				return;
			if (kpos)
				ihist_cur = ihist_cur->prev;
			while (kpos--)
				print("\b");
			memset(kbuf, 0, KBUF_SIZE);
			strcpy(kbuf, ihist_cur->str);
			kpos = strlen(kbuf);
			print(kbuf);
			return;
		}
	case 0xD0:{		// Arrow_DOWN
			if (!ihist_cur || !ihist_cur->next)
				return;
			if (kpos)
				ihist_cur = ihist_cur->next;
			while (kpos--)
				print("\b");
			memset(kbuf, 0, KBUF_SIZE);
			strcpy(kbuf, ihist_cur->str);
			kpos = strlen(kbuf);
			print(kbuf);
			return;
		}
	default:
		break;
	}
	if (~scancode & 0x80) {	// key_down
		switch (scancode) {
		case 0x1C:{	// Enter
				if (!kpos) {
					memset(kbuf, 0, KBUF_SIZE);
					if (ihist_cur && ihist_cur->str) {
						strcpy(kbuf, ihist_cur->str);
						kpos = strlen(kbuf);
						print(kbuf);
					}
				}
				kbuf[kpos] = 0;
				ihist_cur = strlist_end(ihist);
				if (strcmp(ihist_cur->str, kbuf)) {
					strlist_add(ihist, kbuf, 0);
					ihist_cur = ihist_cur->next;
				}
				kpos = 0;
				print("\n");
				parse(kbuf);
				exec();
				if ((status & STAT_RUN) == 0)
					print(ask_input);
				memset(kbuf, 0, KBUF_SIZE);
				break;
			}
		case 0x01:{	// Escape
				ihist_cur = strlist_end(ihist);
				kpos = 0;
				print
				    ("\r                                     \
                                \r");
				memset(kbuf, 0, KBUF_SIZE);
				print(ask_input);
				break;
			}
		case 0x0E:	// Backspace
				ihist_cur = strlist_end(ihist);
				if (kpos) {
					print("\b \b");
					kbuf[kpos--] = 0;
					kbuf[kpos] = 0;
				}
				break;
		case 0x3F:	// F5
				ihist_cur = strlist_end(ihist);
				argc = 0;
				usr_run();
				break;
		case 0x42:	// F8
				usr_step();
				break;
		case 0x44:	// F10
				usr_next();
				break;
		case 0x57:	// F11
				usr_ncall();
				break;
		case 0x58:	// F12
				usr_ret();
				break;
		default:{
				char c;
				if (kbd_state & SHIFT_STATE)
					c = shift_map[scancode];
				else if (kbd_state & ALTGR_STATE)
					c = altgr_map[scancode];
				else if (kbd_state & CTRL_STATE)
					c = ctrl_map[scancode];
				else
					c = plain_map[scancode];
				if (is_sym(c) && kpos < KBUF_SIZE) {
					kbuf[kpos++] = c;
					print("%c", c);
				}
			}
		}
	}
}

__asm__(
"irq1:\n"
	"pusha\n"
	"inb	$0x60, %al\n"
	"movb	%al, scancode\n"
	"inb	$0x64, %al\n"
	"movb	%al, kbd_status\n"

	"call	do_irq1\n"

	"movb	$0x20, %al\n"
	"outb	%al, $0x20\n"
	"outb	%al, $0xA0\n"
	"popa\n"
	"iret\n"
	);
