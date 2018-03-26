;-----------------------------------
;
;	AntiVM: CPUID and friends
;
;-----------------------------------

		section .text
		global _start
_start:
	
		; "CPUID": This instruction is executed with EAX=1
		; as input, the return value describes the processors 
		; features. The 31st bit of ECX on a physical machine 
		; will be equal to 0. On a guest VM it will equal to 1
		xor 	eax, eax
		xor 	ebx, ebx ; Various garbage instructions are being placed here
		mov 	ebx, ebx ; to see if an automated system can still pick up
		inc  	ebx 	 ; on the same malicious behavior
		inc 	eax
		cpuid
		inc 	ecx
		dec 	ecx
		xor 	ebx, ebx
		inc 	ebx
		bt  	ecx, 0x1f
		jb 	vmdetected	
exit:
		xor eax, eax
		inc eax
		int 0x80		
vmdetected:
		mov eax, 4
		mov ebx, 1
		mov ecx, msg
		mov edx, len
		int 0x80
		jmp exit
		
		section .data
msg 		db 'VM Detected!', 0xa
len 		equ $ - msg
