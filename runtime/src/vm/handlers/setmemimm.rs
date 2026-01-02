use iced_x86::code_asm::{byte_ptr, r12, r13, rax, rcx, rdi, rdx, rsi};

use crate::{
    runtime::{FnDef, Runtime},
    vm::stack,
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);
    // push rsi
    stack::push(rt, rsi);
    // push rdi
    stack::push(rt, rdi);

    // mov r12, rdx
    rt.asm.mov(r12, rdx).unwrap();

    // mov rdx, r12
    rt.asm.mov(rdx, r12).unwrap();
    // call ...
    stack::call(rt, rt.func_labels[&FnDef::ComputeAddress]);

    // mov r12, rdx
    rt.asm.mov(r12, rdx).unwrap();

    // movzx r13, [r12] -> size
    rt.asm.movzx(r13, byte_ptr(r12)).unwrap();
    // add r12, 0x1
    rt.asm.add(r12, 0x1).unwrap();

    // mov rsi, r12
    rt.asm.mov(rsi, r12).unwrap();
    // mov rdi, rax
    rt.asm.mov(rdi, rax).unwrap();
    // mov rcx, r13
    rt.asm.mov(rcx, r13).unwrap();

    // cld
    rt.asm.cld().unwrap();

    // rep movsb
    rt.asm.rep().movsb().unwrap();

    // mov rax, rsi
    rt.asm.mov(rax, rsi).unwrap();

    // pop rdi
    stack::pop(rt, rdi);
    // pop rsi
    stack::pop(rt, rsi);
    // pop r13
    stack::pop(rt, r13);
    // pop r12
    stack::pop(rt, r12);
    // ret
    stack::ret(rt);
}
