;-----------------------------------
;
;	AntiVM: CPUID and friends
;
;-----------------------------------

MB_ICONERROR		equ		10h
MB_ICONINFORMATION	equ 	40h
MB_SETFOREGROUND	equ		00010000h

		extern	_ExitProcess@4:proc
		extern	_MessageBoxA@16:proc
		
		global	_start
		
		SECTION	.rdata
msg:	db		'Virtual Environment Detected!', 0
title:	db  	'Alerta', 0
vmware: db 		'VMwareVMware', 0
		
		SECTION	.text
_start:
	
		; "CPUID": This instruction is executed with EAX=1
		; as input, the return value describes the processors 
		; features. The 31st bit of ECX on a physical machine 
		; will be equal to 0. On a guest VM it will equal to 1
		xor 	eax, eax
		inc 	eax
		cpuid
		bt  	ecx, 0x1f
		jb 		vmdetected
		
		
		; “Hypervisor brand”: by calling CPUID with EAX=0x40000000, 
		; the return value will be the virtualization vendor string 
		; in EBX, ECX, and EDX.
		;
		;	Microsoft: “Microsoft HV”
		;	VMware   : “VMwareVMware”
		mov 	eax, 0x40000000
		cpuid
		mov 	edi, vmware
		mov 	eax, ebx
		scasd
		mov 	eax, ecx
		scasd
		mov 	eax, edx
		scasd
		je  	vmdetected
		
		
		; IN – “VMWare Magic Number”: Only for VMware environment. 
		; In VMWare, communication with the host is done through a 
		; specific I/O port. The code below will execute successfully 
		; if running inside a VM. Otherwise it will fail.
		;mov 	eax, 0x564D5868 ; VMXh
		;mov 	edx, 0x5658
		;in  	eax, dx			; if not in VMware, program generates an exception. 
		
		;cmp 	ebx, 0x564D5868
		;setz	cl
		
		; MMX: an Intel instruction set, designed for faster processing of graphical applications.
		; These are usually not supported in Virtual Machines so their absence may indicate that the malware is running in a VM.
		
		
		jmp 	exit
		
vmdetected:
		push 	MB_ICONINFORMATION | MB_SETFOREGROUND
		push 	title
		push 	msg
		push 	0
		call 	_MessageBoxA@16
exit:
		xor 	eax, eax
		push 	eax
		call 	_ExitProcess@4
		
		
