.code

__read_tr proc
    str rax
    ret
__read_tr endp

_cli proc
    cli 
    ret
_cli endp

_sti proc
    sti 
    ret
_sti endp

__read_cs proc
    mov ax, cs
    movzx rax, ax
    ret
__read_cs endp

__read_ss proc
    mov ax, ss
    movzx rax, ax
    ret
__read_ss endp

__read_rsp proc
    mov rax, rsp
    add rax, 8

    ret
__read_rsp endp

__read_r15 proc
    mov rax, r15
    ret
__read_r15 endp

__write_tr proc
    ltr cx
    ret
__write_tr endp

__write_ss proc
    mov ss, cx
    ret
__write_ss endp

__write_cs proc
    push rbx

    ; SS
    mov rbx, ss
    push rbx

    ; Rsp
    mov rbx, rsp
    add rbx, 8
    push rbx
    
    ; Rflags
    pushfq

    ; CS
    movzx rcx, cx ; 16 byte argument passed
    push rcx

    ; Rip
    lea rbx, [continue]
    push rbx
   
    iretq

continue:
    
    pop rbx
    ret
__write_cs endp

 ; Sidt
 __lock_sidt proc
   db 0F0h  ; lock prefix
   sidt qword ptr [rcx]
   ret
 __lock_sidt endp

 __ss_fault_sidt proc
    mov rax, rsp ; Safe rsp into rax

    mov rsp, 4AAAAAAAA555A555h ; Mov some non canonical value into rsp
    sidt qword ptr [rsp] ; #SS should be thrown here
    mov rsp, rax

    ret
 __ss_fault_sidt endp

__gp_fault_sidt proc
    mov rax, 4AAAAAAAA555A555h ; Mov some non canonical value into rax
    sidt qword ptr [rax] ; #GP should be thrown here

    ret
__gp_fault_sidt endp


; lidt
 __lock_lidt proc
   db 0F0h  ; lock prefix
   lidt fword ptr [rcx]
   ret
 __lock_lidt endp

 __ss_fault_lidt proc
    mov rax, rsp ; Safe rsp into rax

    mov rsp, 4AAAAAAAA555A555h ; Mov some non canonical value into rsp
    lidt fword ptr [rsp] ; #SS should be thrown here
    mov rsp, rax ; Restore if not

    ret
 __ss_fault_lidt endp

__gp_fault_lidt proc
    mov rax, 4AAAAAAAA555A555h ; Mov some non canonical value into rax
    lidt fword ptr [rax] ; #GP should be thrown here

    ret
__gp_fault_lidt endp

; other shit
__cause_ss proc
    mov rax, rsp                  ; Save current stack pointer
    mov rsp, 4AAAAAAAA555A555h   ; Set RSP to a non-canonical value
    mov qword ptr [rsp], rax          ; This should cause a #SS fault
    mov rsp, rax                  ; Restore original RSP (this line won't be reached if #SS occurs)
    ret
__cause_ss endp

get_proc_number proc
    push rbx
    push rcx
    push rdx

    xor  eax, eax            ; Clear eax
    mov  eax, 0Bh            ; Set eax to leaf 0x0B
    xor  ecx, ecx            ; Set ecx to 0 (subleaf 0)
    cpuid

    mov  eax, edx ; Save apic id

    pop  rdx
    pop  rcx
    pop  rbx

    ret
get_proc_number endp

__getpcr proc
    mov rax, qword ptr gs:[18h]
	ret
__getpcr endp

end