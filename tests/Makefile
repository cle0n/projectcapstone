PROGRAM=WLOOP
CC=gcc
output_COUNT=`ls outdir | grep $(PROGRAM) | wc -l`
src_COUNT=`ls asmsrc | grep $(PROGRAM) | wc -l`
str=`ls asmsrc`
count=`ls asmsrc | wc -l`

args=`echo $(filter-out $@,$(MAKECMDGOALS))`

# 	other way:
#	ld $(PROGRAM).o -o $(PROGRAM).out -dynamic-linker /lib/ld-linus.so.2 -lc -melf_i386
asm32: $(PROGRAM).asm
	nasm -felf32 $(PROGRAM).asm
	$(CC) -m32 -nostartfiles $(PROGRAM).o -o $(PROGRAM).out
	rm $(PROGRAM).o

asm64: $(PROGRAM).asm
	nasm -felf64 $(PROGRAM).asm
	$(CC) -nostartfiles $(PROGRAM).o -o $(PROGRAM).out
	rm $(PROGRAM).o

move:
	@#echo $(filter-out $@,$(MAKECMDGOALS))
	@if [ ! -f outdir/$(PROGRAM)0.out ]; then PROGRAM=$(PROGRAM)0; fi;
	@mv $(PROGRAM).out outdir/$(PROGRAM)$(output_COUNT).out
	@mv $(PROGRAM).asm asmsrc/$(PROGRAM)$(src_COUNT).asm

init:
	@mkdir outdir
	@mkdir asmsrc

new:
	cp asmsrc/$(PROGRAM)$$(($(src_COUNT) - 1)).asm .
%:
	@:

c32: printloop.c
	$(CC) -m32 -o printloop printloop.c

c64: printloop.c
	$(CC) -o printloop printloop.c

clean:
	rm $(PROGRAM).out
