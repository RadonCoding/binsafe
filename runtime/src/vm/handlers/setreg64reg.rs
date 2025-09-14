use iced_x86::code_asm::{byte_ptr, ptr, r8, r9, rax, rcx, rdx};

use crate::runtime::Runtime;

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // movzx rax, [rdx] -> dst
    rt.asm.movzx(rax, byte_ptr(rdx)).unwrap();
    // dec rax
    rt.asm.dec(rax).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // movzx r8, [rdx] -> src
    rt.asm.movzx(r8, byte_ptr(rdx)).unwrap();
    // dec r8
    rt.asm.dec(r8).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // mov r9, [rcx + r8 * 8]
    rt.asm.mov(r9, ptr(rcx + r8 * 8)).unwrap();
    // mov [rcx + rax * 8], r9
    rt.asm.mov(ptr(rcx + rax * 8), r9).unwrap();

    // mov rax, rdx
    rt.asm.mov(rax, rdx).unwrap();
    // ret
    rt.asm.ret().unwrap();
}
