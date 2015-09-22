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
#include <linux/string.h>
#include "include/kdbg.h"

static strlist *strlist_end(strlist *list)
{
	if (!list)
		return 0;
	while (list->next)
		list = list->next;
	return list;
}

static strlist *strlist_find_str(strlist *list, char *str)
{
	if (list && strlen(str))
		do {
			int len = strlen(list->str);
			if (len && !strncmp(list->str, str, len))
				return list;
		} while ((list = list->next) != 0);
	return 0;
}

static strlist *strlist_find_val(strlist *list, unsigned int val)
{
	if (list)
		do {
			if (list->val == val)
				return list;
		} while ((list = list->next) != 0);
	return 0;
}

static strlist *strlist_init()
{
	strlist *list = (strlist *)kmalloc(sizeof(strlist), GFP_ATOMIC);
	list->next = list->prev = 0;
	list->str = "";
	list->val = 0;
	return list;
}

static void strlist_clean(strlist *list)
{
	if (list) {
		while (list = list->next)
			kfree(list->prev);
		kfree(list);
	}
}

static int strlist_add(strlist *list, char *str, unsigned int val)
{
	if (!list)
		return 0;

	while (list->next)
		list = list->next;
	list->next = (strlist *)
		kmalloc(sizeof(strlist), GFP_ATOMIC);

	list->next->prev = list;
	list = list->next;
	list->next = 0;
	list->str = (char *) kmalloc(strlen(str), GFP_ATOMIC);
	strcpy(list->str, str);
	list->val = val;
	return	1;
}
