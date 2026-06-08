use iced_x86::code_asm::{r8, r9, rax, rcx, rdx};

use crate::{
    runtime::Runtime,
    vm::bytecode::VMReg,
    vm::utils::{self, scratch, stack},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // mov r8, [rcx + ...]; mov r9, [r8]
    utils::vreg::load_mem(rt, rcx, VMReg::Rsp, r8, r9);
    // add [rcx + ...], 0x8
    utils::vreg::add_imm(rt, rcx, 0x8, VMReg::Rsp);

    // store r9
    scratch::store(rt, rcx, r9);

    // mov rax, rdx
    rt.asm.mov(rax, rdx).unwrap();
    // ret
    stack::ret(rt);
}
