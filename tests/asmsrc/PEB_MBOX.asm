
        MB_ICONINFORMATION  equ     40h
        MB_SETFOREGROUND    equ     00010000h

        global  _start

        SECTION .text
_start:
        push    ebp
        mov     ebp, esp
        mov     eax, [fs:0x30]                          ; PEB
        mov     eax, dword [eax + 0xC]                  ; PEB->Ldr
        mov     esi, dword [eax + 0x14]                 ; PEB->Ldr->InMemoryOrderModuleList
        lodsd                                           ; Get second module (NTDLL.dll)
        xchg    eax, esi
        lodsd                                           ; Get third module (KERNEL32.dll)
        mov     ebx, dword [eax + 0x10]                 ; _LDR_DATA_TABLE_ENTRY->DllBase (base of KERNEL32.dll)
        mov     edx, dword [ebx + 0x3C]                 ; base + e_lfanew = PE Header
        mov     edx, dword [edx + ebx + 0x78]           ; export table RVA
        mov     esi, dword [edx + ebx + 0x20]           ; AddressOfNames RVA
        add     esi, ebx                                ; AddressOfNames
        xor     ecx, ecx                                ; ordinal tracker
L0:
        inc     ecx
        lodsd                                           ; Get name offset from AddressOfNames
        cmp     dword [eax + ebx], 0x50746547           ; compare first 4 bytes of API name (GetP)
        jnz     L0
        cmp     dword [eax + ebx + 0x4], 0x41636f72     ; compare next 4 bytes (rocA)
        jnz     L0
        cmp     dword [eax + ebx + 0x8], 0x65726464     ; compare next 4 bytes (ddre)
        jnz     L0
        mov     esi, dword [edx + ebx + 0x24]           ; export table RVA + base + 0x24 = ordinal table RVA
        add     esi, ebx                                ; esi = ordinals table
        mov     cx, word [esi + ecx * 2]                ; get function index
        mov     esi, dword [edx + ebx + 0x1C]           ; get function address table RVA
        add     esi, ebx                                ; esi = Function address table
        mov     edx, dword [esi + ecx * 4 - 4]          ; get API RVA
        add     edx, ebx                                ; edx = API (GetProcAddress)
        push    edx                                     ; save it on the stack
        call    L7
        db      'ExitProcess', 0
L7:
        push    ebx                                     ; ebx = KERNEL32.dll base
        call    edx                                     ; GetProcAddress(ebx, 'ExitProcess')
        push    eax                                     ; save it
        call    L1
        db      'LoadLibraryA', 0
L1:
        push    ebx
        call    dword [ebp - 0x4]                       ; GetProcAddress(ebx, 'LoadLibraryA')
        push    eax                                     ; save it
        call    L2
        db      'user32.dll', 0
L2:
        call    eax                                     ; LoadLibraryA('user32.dll')
        call    L3
        db      'MessageBoxA', 0
L3:
        push    eax                                     ; eax = USER32.dll base
        call    dword [ebp - 0x4]                       ; GetProcAddress(eax, 'MessageBoxA')
        push    eax                                     ; save it
        push    MB_ICONINFORMATION | MB_SETFOREGROUND
        call    L4
        db      'Process', 0
L4:
        call    L5
        db      'Hello World', 0
L5:
        xor     eax, eax
        push    eax
        call    dword [ebp - 0x10]                      ; MessageBoxA(NULL, 'Hello World', 'Process', 0x10040)
        call    dword [ebp - 0x8]                       ; ExitProcess(0);
