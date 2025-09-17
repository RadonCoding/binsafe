use iced_x86::code_asm::{dword_ptr, r8, rax, rcx, rdx};

use crate::{
    runtime::Runtime,
    vm::{bytecode::VMReg, utils},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // mov rax, 0x8; sub [rcx + ...], rax
    utils::sub_vreg_imm_64(rt, rcx, rax, 0x8, VMReg::Rsp);

    // mov r8, [rcx + ...]
    utils::load_vreg_reg_64(rt, rcx, VMReg::Rip, r8);
    // mov [rcx + ...], r8
    utils::store_vmreg_memory_64(rt, rcx, rax, r8, VMReg::Rsp);

    // movsxd rax, [rdx] -> dst
    rt.asm.movsxd(rax, dword_ptr(rdx)).unwrap();
    // add rdx, 0x4
    rt.asm.add(rdx, 0x4).unwrap();

    // add [rcx + ...], rax
    utils::add_vreg_reg_64(rt, rcx, rax, VMReg::Rip);

    // mov rax, rdx
    rt.asm.mov(rax, rdx).unwrap();
    // ret
    rt.asm.ret().unwrap();
}
