use iced_x86::code_asm::{r12, r8, r9, rax, rcx};

use crate::{
    runtime::Runtime,
    vm::bytecode::VMReg,
    vm::utils::{self, scratch},
};

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    // load r9
    scratch::load(rt, r12, r9);

    // sub [r12 + ...], 0x8
    utils::vreg::sub_imm(rt, r12, 0x8, VMReg::Rsp);
    // mov r8, [r12 + ...]; mov [r8], r9
    utils::vreg::store_mem(rt, r12, VMReg::Rsp, r8, r9);

    // mov rax, rcx
    rt.asm.mov(rax, rcx).unwrap();
    // ret
    rt.asm.ret().unwrap();
}
