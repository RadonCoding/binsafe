use iced_x86::code_asm::{
    ecx, ptr, r10, r11, r12, r13, r14, r15, r8, r8d, r9, rax, rbp, rbx, rcx, rdi, rdx, rsi, rsp,
    AsmRegister64,
};

use crate::{
    runtime::{DataDef, FnDef, Runtime},
    vm::{
        bytecode::{VMReg, VM_REG_COUNT},
        stack, utils,
    },
};

pub const VM_STATE_SIZE: usize = VM_REG_COUNT * 8;

const VREG_TO_REG: &[(VMReg, AsmRegister64)] = &[
    (VMReg::Rcx, rcx),
    (VMReg::Rdx, rdx),
    (VMReg::Rbx, rbx),
    (VMReg::Rbp, rbp),
    (VMReg::Rsi, rsi),
    (VMReg::Rdi, rdi),
    (VMReg::R8, r8),
    (VMReg::R9, r9),
    (VMReg::R10, r10),
    (VMReg::R11, r11),
    (VMReg::R12, r12),
    (VMReg::R13, r13),
    (VMReg::R14, r14),
    (VMReg::R15, r15),
];

// void (unsigned int)
pub fn build(rt: &mut Runtime) {
    // push rax
    rt.asm.push(rax).unwrap();
    // lea rax, [...]
    rt.asm
        .lea(rax, ptr(rt.data_labels[&DataDef::VmState]))
        .unwrap();

    for (vreg, reg) in VREG_TO_REG {
        // mov [rax + ...], ...
        utils::mov_vreg_reg_64(rt, rax, *reg, *vreg);
    }

    // pop rcx
    rt.asm.pop(rcx).unwrap();
    // mov [rax + ...], ...
    utils::mov_vreg_reg_64(rt, rax, rcx, VMReg::Rax);

    // pushfq
    rt.asm.pushfq().unwrap();
    // pop rcx
    rt.asm.pop(rcx).unwrap();
    // mov [rax + ...], rcx
    utils::mov_vreg_reg_64(rt, rax, rcx, VMReg::Flags);

    // pop rcx -> offset
    rt.asm.pop(rcx).unwrap();
    // lea rdx, [...]
    rt.asm
        .lea(rdx, ptr(rt.data_labels[&DataDef::VmCode]))
        .unwrap();
    // add rdx, rcx
    rt.asm.add(rdx, rcx).unwrap();

    // mov rcx, gs:[0x60] -> PEB *TEB->ProcessEnvironmentBlock
    rt.asm.mov(rcx, ptr(0x60).gs()).unwrap();
    // mov rcx, [rcx + 0x10] -> VOID *PEB->ImageBaseAddress
    rt.asm.mov(rcx, ptr(rcx + 0x10)).unwrap();
    // mov r8d, [rdx] -> next ip
    rt.asm.mov(r8d, ptr(rdx)).unwrap();
    // add rdx, 0x4
    rt.asm.add(rdx, 0x4).unwrap();
    // add rcx, r8d
    rt.asm.add(rcx, r8).unwrap();
    // add [rax + ...], rcx
    utils::mov_vreg_reg_64(rt, rax, rcx, VMReg::Rip);

    // call ...
    rt.asm
        .call(rt.func_labels[&FnDef::InitializeStack])
        .unwrap();

    // mov [rax + ...], rsp
    utils::mov_vreg_reg_64(rt, rax, rsp, VMReg::Rsp);

    // lea rcx, [...]
    rt.asm
        .lea(rcx, ptr(rt.data_labels[&DataDef::VmState]))
        .unwrap();
    // call ...
    stack::call(rt, rt.func_labels[&FnDef::VmDispatch]);

    // lea rax, [...]
    rt.asm
        .lea(rax, ptr(rt.data_labels[&DataDef::VmState]))
        .unwrap();

    // mov rsp, [rax + ...]
    utils::mov_reg_vreg_64(rt, rax, VMReg::Rsp, rsp);

    // mov rcx, [...]
    utils::mov_reg_vreg_64(rt, rax, VMReg::Flags, rcx);
    // push rcx
    rt.asm.push(rcx).unwrap();
    // popfq
    rt.asm.popfq().unwrap();

    for (vreg, reg) in VREG_TO_REG {
        // mov ...,  [rax + ...]
        utils::mov_reg_vreg_64(rt, rax, *vreg, *reg);
    }

    // push [rax + ...]
    utils::push_vreg_64(rt, rax, VMReg::Rip);

    // mov rax, [rax + ...]
    utils::mov_reg_vreg_64(rt, rax, VMReg::Rax, rax);

    // ret
    rt.asm.ret().unwrap();
}
