use iced_x86::code_asm::{eax, r8, r12, rax, rdx};

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{VMFlag, VMReg},
        utils::{self},
    },
};

// void (void)
pub fn build(rt: &mut Runtime) {
    // pop rax
    rt.asm.pop(rax).unwrap();
    // pop rdx
    rt.asm.pop(rdx).unwrap();
    // push rax
    rt.asm.push(rax).unwrap();

    // mov eax, [r12 + ...]
    utils::vreg::load_reg32(rt, r12, VMReg::Flags, eax);

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

    // mov [r12 + ...], eax
    utils::vreg::store_reg32(rt, r12, eax, VMReg::Flags);

    // ret
    rt.asm.ret().unwrap();
}
