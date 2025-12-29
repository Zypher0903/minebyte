; Minebyte Assembly Module
; Optimization for Nonce Incrementing
; Platform: x86_64 NASM

section .text
global fast_nonce_inc

; void fast_nonce_inc(uint64_t* nonce)
; RDI (System V AMD64 ABI) or RCX (Microsoft x64 ABI) contains pointer to nonce

fast_nonce_inc:
    ; Check platform convention (assuming MSVC/Windows RCX, but handling RDI for *nix compat)
    ; In a real build system, this would be defined by macros
    
    ; Simple atomic increment logic (though single thread here)
    inc qword [rcx]     ; Increment value at memory address in RCX (Windows)
    ret
