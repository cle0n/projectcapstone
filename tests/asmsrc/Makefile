INFILE=`basename -s .asm $(in)`

asm32:
	@nasm -felf32 $(in)
	@gcc -m32 -s -nostartfiles $(INFILE).o -o program
	@rm $(INFILE).o
