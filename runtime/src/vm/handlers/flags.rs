use iced_x86::code_asm::{eax, r12, r8, rax, rcx, rdx};

use crate::{
    runtime::Runtime,
    vm::{bytecode::VMReg, utils},
};

pub fn build(rt: &mut Runtime) {
    // pop rax
    rt.asm.pop(rax).unwrap();
    // pop rdx
    rt.asm.pop(rdx).unwrap();
    // push rax
    rt.asm.push(rax).unwrap();

    // mov eax, [r12 + ...]
    utils::vreg::load_reg32(rt, r12, VMReg::Flags, eax);

    // mov r8, rcx
    rt.asm.mov(r8, rcx).unwrap();
    // not r8
    rt.asm.not(r8).unwrap();
    // and rax, r8
    rt.asm.and(rax, r8).unwrap();

    // and rdx, rcx
    rt.asm.and(rdx, rcx).unwrap();
    // or rax, rdx
    rt.asm.or(rax, rdx).unwrap();

    // mov [r12 + ...], eax
    utils::vreg::store_reg32(rt, r12, eax, VMReg::Flags);

    // ret
    rt.asm.ret().unwrap();
}
