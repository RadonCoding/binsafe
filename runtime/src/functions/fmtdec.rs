use iced_x86::code_asm::{byte_ptr, cl, dl, ptr, r8, r9, rax, rcx, rdx};

use crate::runtime::Runtime;

// void (char*, unsigned long)
pub fn build(rt: &mut Runtime) {
    let mut convert_loop = rt.asm.create_label();
    let mut is_alpha = rt.asm.create_label();

    // mov rax, rdx
    rt.asm.mov(rax, rdx).unwrap();
    // mov r8, rcx
    rt.asm.mov(r8, rcx).unwrap();
    // mov r9, 60
    rt.asm.mov(r9, 60u64).unwrap();

    rt.asm.set_label(&mut convert_loop).unwrap();
    {
        // mov rcx, r9
        rt.asm.mov(rcx, r9).unwrap();
        // mov rdx, rax
        rt.asm.mov(rdx, rax).unwrap();
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
            // mov [r8], dl
            rt.asm.mov(ptr(r8), dl).unwrap();
            // inc r8
            rt.asm.inc(r8).unwrap();
            // sub r9, 4
            rt.asm.sub(r9, 4).unwrap();
            // jge ...
            rt.asm.jge(convert_loop).unwrap();
        }
    }
    // mov [r8], 0x0
    rt.asm.mov(byte_ptr(r8), 0x0).unwrap();
    // ret
    rt.asm.ret().unwrap();
}
