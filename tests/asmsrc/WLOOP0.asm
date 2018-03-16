;----------------------------------------
;
;	while loop construct #0 (64-bit)
;	with RIP relative addressing
;
;	build:
;	nasm -felf64 WLOOP.asm
;	gcc -nostartfiles WLOOP.o -o WLOOP.out
;
;----------------------------------------

		extern	puts
		extern	exit

		global	_start
		
		SECTION	.data
msg:	db	'Hello World!', 0

;----------------------------------------
;
;	GLOBAL:
;		char	*msg = "Hello World!";
;	LOCAL:
;		long	ret = 4;
;
;	while(ret-- > 0)
;		puts("Hello World!");
;
;----------------------------------------

%macro	ccall 1
		call	%1 WRT ..plt
%endmacro


		SECTION	.text
_start:
		push	rbp
		mov		rbp, rsp
		sub		rsp, 8
		mov		qword [rbp - 8], 4
		jmp		L0
L1:
		lea		rdi, [rel + msg]
		ccall	puts
L0:
		mov		rax, qword [rbp - 8]
		lea		rdx, [rax - 1]
		mov		qword [rbp - 8], rdx
		test	rax, rax
		jg		L1
LX:
		ccall	exit

; SHIFT + K over name of C function
; looks up its manpage and opens it what.
