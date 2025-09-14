use iced_x86::code_asm::{byte_ptr, ptr, r8, rax, rcx, rdx};

use crate::runtime::Runtime;

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // movzx rax, [rdx] -> reg
    rt.asm.movzx(rax, byte_ptr(rdx)).unwrap();
    // dec rax
    rt.asm.dec(rax).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // mov r8, [rdx] -> imm
    rt.asm.mov(r8, ptr(rdx)).unwrap();
    // add rdx, 0x8
    rt.asm.add(rdx, 0x8).unwrap();

    // mov [rcx + rax * 8], r8
    rt.asm.mov(ptr(rcx + rax * 8), r8).unwrap();

    // mov rax, rdx
    rt.asm.mov(rax, rdx).unwrap();
    // ret
    rt.asm.ret().unwrap();
}
