use iced_x86::code_asm::{byte_ptr, ptr, r13, r14, r15, rax, rcx, rdx};

use crate::runtime::{FnDef, Runtime};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();
    // push r15
    rt.asm.push(r15).unwrap();

    // mov r13, rcx
    rt.asm.mov(r13, rcx).unwrap();
    // mov r14, rdx
    rt.asm.mov(r14, rdx).unwrap();

    // movzx r15, [r14] -> dst
    rt.asm.movzx(r15, byte_ptr(r14)).unwrap();
    // dec r15
    rt.asm.dec(r15).unwrap();
    // add r14, 0x1
    rt.asm.add(r14, 0x1).unwrap();

    // mov rcx, r13
    rt.asm.mov(rcx, r13).unwrap();
    // mov rdx, r14
    rt.asm.mov(rdx, r14).unwrap();
    // call ...
    rt.asm
        .call(rt.func_labels[&FnDef::ComputeEffectiveAddress])
        .unwrap();

    // mov r14, rdx
    rt.asm.mov(r14, rdx).unwrap();

    // mov rax, [rax]
    rt.asm.mov(rax, ptr(rax)).unwrap();
    // mov [r13 + r15*8], rcx
    rt.asm.mov(ptr(r13 + r15 * 8), rax).unwrap();

    // mov rax, r14
    rt.asm.mov(rax, r14).unwrap();
    // pop r15
    rt.asm.pop(r15).unwrap();
    // pop r14
    rt.asm.pop(r14).unwrap();
    // pop r13
    rt.asm.pop(r13).unwrap();
    // ret
    rt.asm.ret().unwrap();
}
