use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{VMFlag, VMReg},
        utils,
    },
};
use iced_x86::code_asm::{eax, r12, r8, r8b, r8d, rax, rcx, rdx};

const FLAGS: [(VMFlag, u32); 9] = [
    (VMFlag::Carry, 0),
    (VMFlag::Parity, 2),
    (VMFlag::Auxiliary, 4),
    (VMFlag::Zero, 6),
    (VMFlag::Sign, 7),
    (VMFlag::Trap, 8),
    (VMFlag::Interrupt, 9),
    (VMFlag::Direction, 10),
    (VMFlag::Overflow, 11),
];

pub fn build(rt: &mut Runtime) {
    // pop rax
    rt.asm.pop(rax).unwrap();
    // pop rdx
    rt.asm.pop(rdx).unwrap();
    // push rax
    rt.asm.push(rax).unwrap();

    // mov eax, [r12 + ...]
    utils::vreg::load_reg32(rt, r12, VMReg::Flags, eax);

    for (flag, bit) in FLAGS {
        // xor r8d, r8d
        rt.asm.xor(r8d, r8d).unwrap();
        // test rax, ...
        rt.asm.test(rax, 1 << bit).unwrap();
        // setnz r8b
        rt.asm.setnz(r8b).unwrap();

        // shl r8d, ...
        rt.asm.shl(r8d, rt.mapper.index(flag) as i32).unwrap();

        // mov eax, ...
        rt.asm
            .mov(eax, !(1 << rt.mapper.index(flag)) as u32)
            .unwrap();
        // or eax, r8d
        rt.asm.or(eax, r8d).unwrap();
    }

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
