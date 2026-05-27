use crate::vm::utils;
use iced_x86::code_asm::{al, ptr, r12, r13, r8, rax, rcx, rdx};

use crate::{
    runtime::{FnDef, Runtime},
    vm::{bytecode::VMReg, stack},
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

    // mov al, [r13]; add r13, 0x1 -> ret
    utils::bytecode::read_byte(rt, r13, al);

    // test al, al
    rt.asm.test(al, al).unwrap();
    // jz ...
    rt.asm.jz(skip_ret).unwrap();

    // sub [r12 + ...], 0x8
    utils::vreg::sub_imm(rt, r12, 0x8, VMReg::Rsp);
    // mov r8, [r12 + ...]
    utils::vreg::load_reg(rt, r12, VMReg::Vex, r8);
    // mov rax, [r12 + ...]; mov [rax], r8
    utils::vreg::store_mem(rt, r12, rax, r8, VMReg::Rsp);

    rt.asm.set_label(&mut skip_ret).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // mov rdx, r13
        rt.asm.mov(rdx, r13).unwrap();
        // call ...
        stack::call(rt, rt.func_labels[&FnDef::VmSib]);
        // mov r13, rdx
        rt.asm.mov(r13, rdx).unwrap();

        // mov rax, [rax]
        rt.asm.mov(rax, ptr(rax)).unwrap();

        // mov [r12 + ...], rax
        utils::vreg::store_reg(rt, r12, rax, VMReg::Vbr);

        // mov rax, r13
        rt.asm.mov(rax, r13).unwrap();
        // pop r13
        stack::pop(rt, r13);
        // pop r12
        stack::pop(rt, r12);
        // ret
        stack::ret(rt);
    }
}
