use iced_x86::code_asm::{
    al, byte_ptr, ecx, ptr, r10, r11, r12, r13, r14, r15, r8, r9, rax, rbp, rbx, rcx, rdi, rdx,
    rsi, rsp, AsmRegister64,
};

use crate::{
    runtime::{DataDef, FnDef, Runtime},
    vm::{bytecode::VMReg, stack, utils},
};

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
    let mut wait_for_lock = rt.asm.create_label();

    // pushfq
    rt.asm.pushfq().unwrap();
    // push rax
    rt.asm.push(rax).unwrap();

    rt.asm.set_label(&mut wait_for_lock).unwrap();
    {
        // mov al, 0x1
        rt.asm.mov(al, 0x1).unwrap();
        // lock xchg [...], al
        rt.asm
            .lock()
            .xchg(ptr(rt.data_labels[&DataDef::VmLock]), al)
            .unwrap();
        // test al, al
        rt.asm.test(al, al).unwrap();
        // jnz ...
        rt.asm.jnz(wait_for_lock).unwrap();
    }

    // lea rax, [...]
    rt.asm
        .lea(rax, ptr(rt.data_labels[&DataDef::VmState]))
        .unwrap();

    for (vreg, reg) in VREG_TO_REG {
        // mov [rax + ...], ...
        utils::mov_vreg_reg_64(rt, rax, *reg, *vreg);
    }

    // pop rcx -> rax
    rt.asm.pop(rcx).unwrap();
    // mov [rax + ...], ...
    utils::mov_vreg_reg_64(rt, rax, rcx, VMReg::Rax);

    // pop rcx -> flags
    rt.asm.pop(rcx).unwrap();
    // mov [rax + ...], rcx
    utils::mov_vreg_reg_64(rt, rax, rcx, VMReg::Flags);

    // pop rcx -> ret
    rt.asm.pop(rcx).unwrap();
    // mov [rax + ...], rcx
    utils::mov_vreg_reg_64(rt, rax, rcx, VMReg::Vip);

    // mov rdx, gs:[0x60] -> PEB *TEB->ProcessEnvironmentBlock
    rt.asm.mov(rdx, ptr(0x60).gs()).unwrap();
    // mov rdx, [rdx + 0x10] -> PVOID PEB->ImageBaseAddress
    rt.asm.mov(rdx, ptr(rdx + 0x10)).unwrap();
    // mov [rax + ...], rcx
    utils::mov_vreg_reg_64(rt, rax, rdx, VMReg::VB);

    // pop rcx -> index
    rt.asm.pop(rcx).unwrap();
    // lea rdx, [...]
    rt.asm
        .lea(rdx, ptr(rt.data_labels[&DataDef::VmTable]))
        .unwrap();
    // lea rdx, [rdx + rcx*8]
    rt.asm.lea(rdx, ptr(rdx + rcx * 8)).unwrap();
    // mov ecx, [rdx] -> displ
    rt.asm.mov(ecx, ptr(rdx)).unwrap();
    // add [rax + ...], rcx
    utils::add_vreg_reg_64(rt, rax, rcx, VMReg::Vip);
    // mov ecx, [rdx + 0x4] -> offset
    rt.asm.mov(ecx, ptr(rdx + 0x4)).unwrap();

    // lea rdx, [...]
    rt.asm
        .lea(rdx, ptr(rt.data_labels[&DataDef::VmCode]))
        .unwrap();
    // add rdx, rcx
    rt.asm.add(rdx, rcx).unwrap();

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
    utils::push_vreg_64(rt, rax, VMReg::Flags);
    // popfq
    rt.asm.popfq().unwrap();

    for (vreg, reg) in VREG_TO_REG {
        // mov ...,  [rax + ...]
        utils::mov_reg_vreg_64(rt, rax, *vreg, *reg);
    }

    // push [rax + ...]
    utils::push_vreg_64(rt, rax, VMReg::Vip);

    // mov rax, [rax + ...]
    utils::mov_reg_vreg_64(rt, rax, VMReg::Rax, rax);

    // mov [...], 0x0
    rt.asm
        .mov(byte_ptr(rt.data_labels[&DataDef::VmLock]), 0x0)
        .unwrap();

    // ret
    rt.asm.ret().unwrap();
}
