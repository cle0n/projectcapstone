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
		bt  	ecx, 0x1f
		jb		vmdetected
_exit:
		call	exit
vmdetected:
		push	msg
		call	puts
		jmp		_exit
