use iced_x86::code_asm::{byte_ptr, cl, dl, ptr, r8, r9, rax, rcx, rdx};

use crate::runtime::Runtime;

// void (char*, unsigned long)
pub fn build(rt: &mut Runtime) {
    let mut convert_loop = rt.asm.create_label();

    let mut is_alpha = rt.asm.create_label();

    // mov rax, rcx
    rt.asm.mov(rax, rcx).unwrap();
    // mov r8, rdx
    rt.asm.mov(r8, rdx).unwrap();
    // mov r9, 0x3c
    rt.asm.mov(r9, 0x3cu64).unwrap();

    rt.asm.set_label(&mut convert_loop).unwrap();
    {
        // mov rcx, r9
        rt.asm.mov(rcx, r9).unwrap();
        // mov rdx, r8
        rt.asm.mov(rdx, r8).unwrap();
        // shr rdx, cl
        rt.asm.shr(rdx, cl).unwrap();
        // and rdx, 0xf
        rt.asm.and(rdx, 0xf).unwrap();
        // add rdx, 0x30
        rt.asm.add(rdx, 0x30).unwrap();
        // cmp rdx, 0x3a
        rt.asm.cmp(rdx, 0x3a).unwrap();
        // jl ...
        rt.asm.jl(is_alpha).unwrap();
        // add rdx, 0x27
        rt.asm.add(rdx, 0x27).unwrap();

        rt.asm.set_label(&mut is_alpha).unwrap();
        {
            // mov [rax], dl
            rt.asm.mov(ptr(rax), dl).unwrap();
            // inc rax
            rt.asm.inc(rax).unwrap();
            // sub r9, 0x4
            rt.asm.sub(r9, 0x4).unwrap();
            // jge ...
            rt.asm.jge(convert_loop).unwrap();
        }
    }
    // mov [rax], 0x0
    rt.asm.mov(byte_ptr(rax), 0x0).unwrap();
    // ret
    rt.asm.ret().unwrap();
}
