use iced_x86::code_asm::{dword_ptr, r8, rax, rcx, rdx};

use crate::{
    runtime::Runtime,
    vm::{bytecode::VMReg, utils},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // mov rax, [rcx + ...]
    utils::load_vmreg(rt, rcx, VMReg::Rsp, rax);
    // sub rax, 0x8
    rt.asm.sub(rax, 0x8).unwrap();
    // mov [rcx + ...], rax
    utils::store_vmreg(rt, rcx, rax, VMReg::Rsp);

    // mov r8, [rcx + ...]
    utils::load_vmreg(rt, rcx, VMReg::Rip, r8);
    // mov [rcx + ...], r8
    utils::store_vmreg_memory(rt, rcx, rax, r8, VMReg::Rsp);

    // movsxd rax, [rdx] -> dst
    rt.asm.movsxd(rax, dword_ptr(rdx)).unwrap();
    // add rdx, 0x4
    rt.asm.add(rdx, 0x4).unwrap();

    // add [rcx + ...], rax
    utils::add_vmreg(rt, rcx, rax, VMReg::Rip);

    // mov rax, rdx
    rt.asm.mov(rax, rdx).unwrap();
    // ret
    rt.asm.ret().unwrap();
}
