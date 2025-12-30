use iced_x86::code_asm::{al, ptr, r12, r13, r8, rax, rcx, rdx};

use crate::{
    runtime::{FnDef, Runtime},
    vm::{bytecode::VMReg, stack, utils},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut skip_ret = rt.asm.create_label();

    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();
    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // mov al, [r13] -> ret
    rt.asm.mov(al, ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();

    // test al, al
    rt.asm.test(al, al).unwrap();
    // jz ...
    rt.asm.jz(skip_ret).unwrap();

    // sub [rcx + ...], 0x8
    utils::sub_vreg_imm_64(rt, rcx, 0x8, VMReg::Rsp);

    // mov r8, [r12 + ...]
    utils::mov_reg_vreg_64(rt, r12, VMReg::Rip, r8);
    // mov rax, [r12 + ...]; mov [rax], r8
    utils::store_vreg_mem_64(rt, r12, rax, r8, VMReg::Rsp);

    rt.asm.set_label(&mut skip_ret).unwrap();

    // mov rcx, r12
    rt.asm.mov(rcx, r12).unwrap();
    // mov rdx, r13
    rt.asm.mov(rdx, r13).unwrap();
    // call ...
    stack::call(rt, rt.func_labels[&FnDef::ComputeAddress]);
    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // mov rax, [rax]
    rt.asm.mov(rax, ptr(rax)).unwrap();
    // mov [r12 + ...], rax
    utils::mov_vreg_reg_64(rt, r12, rax, VMReg::Rip);

    // mov rax, r13
    rt.asm.mov(rax, r13).unwrap();
    // pop r13
    stack::pop(rt, r13);
    // pop r12
    stack::pop(rt, r12);
    // ret
    stack::ret(rt);
}
