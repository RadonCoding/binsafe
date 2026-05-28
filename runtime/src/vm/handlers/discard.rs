use iced_x86::code_asm::{r9, rax, rdx};

use crate::{
    runtime::Runtime,
    vm::utils::{scratch, stack},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // load r9
    scratch::load(rt, r9);

    // mov rax, rdx
    rt.asm.mov(rax, rdx).unwrap();
    // ret
    stack::ret(rt);
}
