use iced_x86::code_asm::{r8, r9, rax, rcx, rdx};

use crate::{
    runtime::Runtime,
    vm::bytecode::VMReg,
    vm::utils::{self, scratch, stack},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // load r9
    scratch::load(rt, rcx, r9);

    // sub [rcx + ...], 0x8
    utils::vreg::sub_imm(rt, rcx, 0x8, VMReg::Rsp);
    // mov r8, [rcx + ...]; mov [r8], r9
    utils::vreg::store_mem(rt, rcx, VMReg::Rsp, r8, r9);

    // mov rax, rdx
    rt.asm.mov(rax, rdx).unwrap();
    // ret
    stack::ret(rt);
}
