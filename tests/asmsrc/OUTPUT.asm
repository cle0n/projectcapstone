;-----------------------------------
;
;	AntiVM: CPUID and friends
;
;-----------------------------------
		
		extern puts
		extern exit

		global _start
		
		section .data
msg:	db		'VM Detected!', 0xa
len:	equ		$ - msg

		section .text
_start:
		mov 	bx, bx
		mov 	cx, cx
		mov		eax, 1
		mov 	ch, ch
		cpuid
		nop
		nop
		bt  	ecx, 0x1f
		jb		vmdetected	
		nop
_exit:
		xchg 	sp, sp
		call	exit
		mov 	ebp, ebp
vmdetected:
		xchg 	ebx, ebx
		push	msg
		xchg 	esp, esp
		xchg 	di, di
		mov 	ecx, ecx
		call	puts
		nop
		mov 	cx, cx
		jmp		_exit
