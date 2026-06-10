use iced_x86::code_asm::{r12, r8, r9, rax, rcx};

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMReg,
        utils::{scratch, vreg},
    },
};

// unsigned char* (unsigned char*)
pub fn build(rt:  &mut Runtime) {
    // load r8
    scratch::load(rt, r12, r8);
    // mov rax, [r12 + ...]; mov r9, [rax]
    vreg::load_mem(rt, r12, VMReg::Rsp, rax, r9);
    // mov [r12 + ...], r9
    vreg::store_reg(rt, r12, r9, VMReg::NBranch);
    // add [r12 + ...], 0x8
    vreg::add_imm(rt, r12, 0x8, VMReg::Rsp);
    // add [r12 + ...], r8
    vreg::add_reg(rt, r12, r8, VMReg::Rsp);

    // mov rax, rcx
    rt.asm.mov(rax, rcx).unwrap();
    // ret
    rt.asm.ret().unwrap();
}
