;--------------------------------------------------------------
;
;	AntiVM: CPUID
;
;--------------------------------------------------------------

		extern exit
		extern puts

		global _start

		SECTION .data
msg:	db		'VMware Detected!', 0

		SECTION .text
_start:
		xor 	eax, eax
		inc 	eax
		cpuid
		test	ecx, ecx
		je 		B1
		inc 	ecx
		mov 	edx, ecx
		dec 	edx
		mov 	ecx, edx
		jmp 	B2
B1:
		inc 	ecx
		inc 	ecx
B2:
		bt  	ecx, 0x1f
		jnb		_exit
		push	msg
		call	puts
_exit:
		call	exit
