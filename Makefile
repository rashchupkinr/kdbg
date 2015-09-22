src0=kdbg
src1=lib
src2=install
src3=int
src4=irq1
src5=int3
src6=int1
src7=mem
src8=break
src9=hbreak
src10=usr
src11=sym
src12=strlist
src13=disasm/disasm

CC=gcc
MODFLAGS := -pipe -DLINUX -O2 -fomit-frame-pointer -I/usr/src/linux/include
LD=ld
LDFLAGS := -m elf_i386 -r -O2

$(src0).o:	obj/$(src1).o	obj/$(src2).o	obj/$(src6).o \
		obj/$(src3).o	obj/$(src4).o	obj/$(src5).o \
		obj/$(src7).o	obj/$(src8).o	obj/$(src9).o \
		obj/$(src10).o	obj/$(src11).o	obj/$(src12).o \
		obj/$(src13).o
	$(LD) $(LDFLAGS) -o $@ $^
	sync

obj/%.o:	%.c include/kdbg.h disasm/disasm.h
	$(CC) $(MODFLAGS) -c $< -o $@

clean:
	rm	obj/*.o
	rm	obj/disasm/*.o
	rm	*.o

%.s:	%.c
	$(CC) -S $(MODFLAGS) $< -o $@
