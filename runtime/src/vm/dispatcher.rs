use iced_x86::code_asm::{byte_ptr, ptr, r12, r13, r14, r8, rax, rcx, rdx};

use crate::{
    runtime::{DataDef, Runtime},
    vm::{bytecode::VMReg, utils},
};

// void (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // push r12
    rt.asm.push(r12).unwrap();
    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();
    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // movzx rax, [r13] -> len
    rt.asm.movzx(rax, byte_ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();
    // add [r12 + ...], rax
    utils::add_vreg_reg_64(rt, r12, rax, VMReg::Rip);

    // mov r14, [r12 + ...]
    utils::mov_reg_vreg_64(rt, r12, VMReg::Rip, rax);

    // movzx rax, [r13] -> op
    rt.asm.movzx(rax, byte_ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();

    // lea r8, [...]
    rt.asm
        .lea(r8, ptr(rt.data_labels[&DataDef::Handlers]))
        .unwrap();
    // mov r8, [r8 + rax*8]
    rt.asm.mov(r8, ptr(r8 + rax * 8)).unwrap();

    // mov rcx, r12
    rt.asm.mov(rcx, r12).unwrap();
    // mov rdx, r13
    rt.asm.mov(rdx, r13).unwrap();
    // call r8
    rt.asm.call(r8).unwrap();

    // cmp [r12 + ...], r14
    utils::cmp_vreg_reg_64(rt, r12, VMReg::Rip, r14);

    // mov r13, rax
    rt.asm.mov(r13, rax).unwrap();

    // pop r14
    rt.asm.pop(r14).unwrap();
    // pop r13
    rt.asm.pop(r13).unwrap();
    // pop r12
    rt.asm.pop(r12).unwrap();
    // ret
    rt.asm.ret().unwrap();
}
