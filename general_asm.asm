.code

; ------------------------------------------------------------
; General Purpose Register Reading/Manipulation
; ------------------------------------------------------------

__read_rsp proc
    mov rax, rsp
    add rax, 8
    ret
__read_rsp endp

__read_r15 proc
    mov rax, r15
    ret
__read_r15 endp

; ------------------------------------------------------------
; Segment Register Reading/Manipulation
; ------------------------------------------------------------

; Read Task Register (TR)
__read_tr proc
    str rax
    ret
__read_tr endp

; Write Task Register (TR)
__write_tr proc
    ltr cx
    ret
__write_tr endp

; Read Code Segment (CS)
__read_cs proc
    mov ax, cs
    movzx rax, ax
    ret
__read_cs endp

; Write Code Segment (CS)
__write_cs proc
    push rbx

    ; Save SS
    mov rbx, ss
    push rbx

    ; Save RSP
    mov rbx, rsp
    add rbx, 8
    push rbx
    
    ; Save RFLAGS
    pushfq

    ; Save CS
    movzx rcx, cx
    push rcx

    ; Save RIP
    lea rbx, [continue]
    push rbx
   
    iretq

continue:
    pop rbx
    ret
__write_cs endp

; Read Data Segment (DS)
__read_ds proc
    mov ax, ds
    movzx rax, ax
    ret
__read_ds endp

; Write Data Segment (DS)
__write_ds proc
    mov ds, cx
    ret
__write_ds endp

; Read Extra Segment (ES)
__read_es proc
    mov ax, es
    movzx rax, ax
    ret
__read_es endp

; Write Extra Segment (ES)
__write_es proc
    mov es, cx
    ret
__write_es endp

; Read Stack Segment (SS)
__read_ss proc
    mov ax, ss
    movzx rax, ax
    ret
__read_ss endp

; Write Stack Segment (SS)
__write_ss proc
    mov ss, cx
    ret
__write_ss endp

; Read FS Segment
__read_fs proc
    mov ax, fs
    movzx rax, ax
    ret
__read_fs endp

; Write FS Segment
__write_fs proc
    mov fs, cx
    ret
__write_fs endp

; Read GS Segment
__read_gs proc
    mov ax, gs
    movzx rax, ax
    ret
__read_gs endp

; Write GS Segment
__write_gs proc
    mov gs, cx
    ret
__write_gs endp

; ------------------------------------------------------------
; CLI/STI Operations
; ------------------------------------------------------------

_cli proc
    cli 
    ret
_cli endp

_sti proc
    sti 
    ret
_sti endp

; ------------------------------------------------------------
; SIDT Operations (Fault Handling and Locking)
; ------------------------------------------------------------

__lock_sidt proc
   db 0F0h  ; lock prefix
   sidt qword ptr [rcx]
   ret
__lock_sidt endp

__ss_fault_sidt proc
    mov rax, rsp               ; Save RSP into RAX
    mov rsp, 4AAAAAAAA555A555h  ; Non-canonical value to trigger #SS
    sidt qword ptr [rsp]        ; SIDT will cause #SS
    mov rsp, rax                ; Restore RSP
    ret
__ss_fault_sidt endp

__gp_fault_sidt proc
    mov rax, 4AAAAAAAA555A555h  ; Non-canonical value to trigger #GP
    sidt qword ptr [rax]        ; SIDT will cause #GP
    ret
__gp_fault_sidt endp

; ------------------------------------------------------------
; LIDT Operations (Fault Handling and Locking)
; ------------------------------------------------------------

__lock_lidt proc
   db 0F0h  ; lock prefix
   lidt fword ptr [rcx]
   ret
__lock_lidt endp

__ss_fault_lidt proc
    mov rax, rsp               ; Save RSP into RAX
    mov rsp, 4AAAAAAAA555A555h  ; Non-canonical value to trigger #SS
    lidt fword ptr [rsp]        ; LIDT will cause #SS
    mov rsp, rax                ; Restore RSP
    ret
__ss_fault_lidt endp

__gp_fault_lidt proc
    mov rax, 4AAAAAAAA555A555h  ; Non-canonical value to trigger #GP
    lidt fword ptr [rax]        ; LIDT will cause #GP
    ret
__gp_fault_lidt endp

; ------------------------------------------------------------
; Special Fault Operations
; ------------------------------------------------------------

__cause_ss proc
    mov rax, rsp               ; Save current RSP into RAX
    mov rsp, 4AAAAAAAA555A555h  ; Set RSP to non-canonical value
    mov qword ptr [rsp], rax    ; Should trigger #SS
    mov rsp, rax               ; Restore RSP (won't be reached if #SS occurs)
    ret
__cause_ss endp

; ------------------------------------------------------------
; Utility Functions
; ------------------------------------------------------------

get_proc_number proc
    push rbx
    push rcx
    push rdx

    xor  eax, eax            ; Clear EAX
    mov  eax, 0Bh            ; CPUID leaf 0x0B (Extended Topology Enumeration)
    xor  ecx, ecx            ; Sub-leaf 0
    cpuid

    mov  eax, edx            ; Save APIC ID in EAX

    pop  rdx
    pop  rcx
    pop rbx

    ret
get_proc_number endp

end
