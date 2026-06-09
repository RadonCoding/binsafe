use iced_x86::code_asm::{r8, r9, rax, rcx, rdx};

use crate::{runtime::Runtime, vm::bytecode::VMReg, vm::utils::vreg};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // mov r8, [rcx + ...]; mov r9, [r8]
    vreg::load_mem(rt, rcx, VMReg::Rsp, r8, r9);
    // mov [rcx + ...], r9
    vreg::store_reg(rt, rcx, r9, VMReg::NBranch);
    // add [rcx + ...], 0x8
    vreg::add_imm(rt, rcx, 0x8, VMReg::Rsp);

    // mov rax, rdx
    rt.asm.mov(rax, rdx).unwrap();
    // ret
    rt.asm.ret().unwrap();
}
