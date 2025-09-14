use iced_x86::code_asm::{ptr, r13, r14, r8, rax, rcx, rdx};

use crate::{
    runtime::{FnDef, Runtime},
    vm::{bytecode::VMReg, utils},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();

    // mov r13, rcx
    rt.asm.mov(r13, rcx).unwrap();
    // mov r14, rdx
    rt.asm.mov(r14, rdx).unwrap();

    // mov rax, [r13 + ...]
    utils::load_vmreg(rt, r13, VMReg::Rsp, rax);
    // sub rax, 0x8
    rt.asm.sub(rax, 0x8).unwrap();
    // mov [r13 + ...], rax
    utils::store_vmreg(rt, r13, rax, VMReg::Rsp);

    // mov r8, [r13 + ...]
    utils::load_vmreg(rt, r13, VMReg::Rip, r8);
    // mov [r13 + ...], r8
    utils::store_vmreg_memory(rt, r13, rax, r8, VMReg::Rsp);

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
    // mov [r13 + ...], rax
    utils::store_vmreg(rt, r13, rax, VMReg::Rip);

    // mov rax, r14
    rt.asm.mov(rax, r14).unwrap();
    // pop r14
    rt.asm.pop(r14).unwrap();
    // pop r13
    rt.asm.pop(r13).unwrap();
    // ret
    rt.asm.ret().unwrap();
}
