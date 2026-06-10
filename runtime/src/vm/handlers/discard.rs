use iced_x86::code_asm::{r12, r9, rax, rcx};

use crate::{runtime::Runtime, vm::utils::scratch};

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    // load r9
    scratch::load(rt, r12, r9);

    // mov rax, rcx
    rt.asm.mov(rax, rcx).unwrap();
    // ret
    rt.asm.ret().unwrap();
}
