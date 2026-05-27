use crate::vm::utils;
use iced_x86::code_asm::{r8, rax, rcx, rdx};

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{VMFlag, VMReg},
        stack,
    },
};

// void (unsigned long*, unsigned long)
pub fn build(rt: &mut Runtime) {
    // mov rax, [rcx + ...]
    utils::vreg::load_reg(rt, rcx, VMReg::Flags, rax);

    const FLAG_MASK: u64 = (1 << VMFlag::Carry as u64)
        | (1 << VMFlag::Parity as u64)
        | (1 << VMFlag::Auxiliary as u64)
        | (1 << VMFlag::Zero as u64)
        | (1 << VMFlag::Sign as u64)
        | (1 << VMFlag::Overflow as u64);

    // mov r8, ...
    rt.asm.mov(r8, !FLAG_MASK).unwrap();
    // and rax, r8
    rt.asm.and(rax, r8).unwrap();

    // mov r8, ...
    rt.asm.mov(r8, FLAG_MASK).unwrap();
    // and rdx, r8
    rt.asm.and(rdx, r8).unwrap();
    // or rax, rdx
    rt.asm.or(rax, rdx).unwrap();

    // mov [rcx + ...], rax
    utils::vreg::store_reg(rt, rcx, rax, VMReg::Flags);

    // ret
    stack::ret(rt);
}
