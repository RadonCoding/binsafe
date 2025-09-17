use iced_x86::code_asm::{byte_ptr, ptr, r8, rax, rcx, rdx};

use crate::{
    runtime::Runtime,
    vm::{bytecode::VMReg, utils},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // mov rax, 0x8; sub [rcx + ...], rax
    utils::sub_vreg_imm_64(rt, rcx, rax, 0x8, VMReg::Rsp);

    // movzx rax, [rdx] -> src
    rt.asm.movzx(rax, byte_ptr(rdx)).unwrap();
    // dec rax
    rt.asm.dec(rax).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // mov r8, [rcx + rax*8]
    rt.asm.mov(r8, ptr(rcx + rax * 8)).unwrap();
    // mov rax, [rcx + ...]; mov [rax], r8
    utils::store_vmreg_memory_64(rt, rcx, rax, r8, VMReg::Rsp);

    // mov rax, rdx
    rt.asm.mov(rax, rdx).unwrap();
    // ret
    rt.asm.ret().unwrap();
}
