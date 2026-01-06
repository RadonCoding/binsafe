use iced_x86::code_asm::{byte_ptr, ptr, r8, rax, rcx, rdx};

use crate::{
    runtime::Runtime,
    vm::{bytecode::VMReg, stack, utils},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // movzx rax, [rdx] -> src
    rt.asm.movzx(rax, byte_ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // sub [rcx + ...], 0x8
    utils::sub_vreg_imm_64(rt, rcx, 0x8, VMReg::Rsp);
    // mov r8, [rcx + rax*8]
    rt.asm.mov(r8, ptr(rcx + rax * 8)).unwrap();
    // mov rax, [rcx + ...]; mov [rax], r8
    utils::store_vreg_mem_64(rt, rcx, rax, r8, VMReg::Rsp);

    // mov rax, rdx
    rt.asm.mov(rax, rdx).unwrap();
    // ret
    stack::ret(rt);
}
