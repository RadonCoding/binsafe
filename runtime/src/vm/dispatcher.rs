use iced_x86::code_asm::{byte_ptr, ptr, r13, r14, r8, rax, rcx, rdx};

use crate::{
    runtime::{DataDef, Runtime},
    vm::bytecode::VMReg,
};

// void (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();

    // mov r13, rcx
    rt.asm.mov(r13, rcx).unwrap();
    // mov r14, rdx
    rt.asm.mov(r14, rdx).unwrap();

    // movzx rax, [r14] -> len
    rt.asm.movzx(rax, byte_ptr(r14)).unwrap();
    // add r14, 0x1
    rt.asm.add(r14, 0x1).unwrap();
    // add [r13 + ...], rax
    rt.asm
        .add(ptr(r13 + (VMReg::Rip as u8 - 1) * 8), rax)
        .unwrap();

    // movzx rax, [r14] -> op
    rt.asm.movzx(rax, byte_ptr(r14)).unwrap();
    // add r14, 0x1
    rt.asm.add(r14, 0x1).unwrap();

    // lea r8, [...]
    rt.asm
        .lea(r8, ptr(rt.data_labels[&DataDef::HANDLERS]))
        .unwrap();
    // mov r8, [r8 + rax*8]
    rt.asm.mov(r8, ptr(r8 + rax * 8)).unwrap();

    // mov rcx, r13
    rt.asm.mov(rcx, r13).unwrap();
    // mov rdx, r14
    rt.asm.mov(rdx, r14).unwrap();
    // call r8
    rt.asm.call(r8).unwrap();

    // mov r14, rax
    rt.asm.mov(r14, rax).unwrap();

    // pop r14
    rt.asm.pop(r14).unwrap();
    // pop r13
    rt.asm.pop(r13).unwrap();
    // ret
    rt.asm.ret().unwrap();
}
