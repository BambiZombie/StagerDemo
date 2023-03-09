EXTRN   getLoadLibraryA: PROC
PUBLIC  myLoadLibrary
PUBLIC	myNtAllocateVirtualMemory

_TEXT   SEGMENT

myLoadLibrary PROC
    movq xmm3, rdx
    xor rdx, rdx
    call getLoadLibraryA
    movq rcx, xmm3
    xorps xmm3, xmm3
    jmp rax
myLoadLibrary ENDP

myNtAllocateVirtualMemory PROC
    mov rbx, rdx                ; backing up the struct as we are going to stomp rdx
    mov rax, [rbx]              ; NtAllocateVirtualMemory
    mov rcx, [rbx + 8h]        ; HANDLE ProcessHandle
    mov rdx, [rbx + 10h]       ; PVOID *BaseAddress
    xor r8, r8                  ; ULONG_PTR ZeroBits
    mov r9, [rbx + 18h]        ; PSIZE_T RegionSize
    mov r10, [rbx + 20h]       ; ULONG Protect
    mov [rsp+30h], r10         ; stack pointer for 6th arg
    mov r10, 3000h             ; ULONG AllocationType
    mov [rsp+28h], r10         ; stack pointer for 5th arg
    jmp rax
myNtAllocateVirtualMemory ENDP

_TEXT   ENDS

END