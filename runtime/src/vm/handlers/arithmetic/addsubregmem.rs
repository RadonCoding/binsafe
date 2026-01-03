use iced_x86::code_asm::{rax, rdx};

use crate::{runtime::Runtime, vm::stack};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // mov rax, rdx
    rt.asm.mov(rax, rdx).unwrap();
    // ret
    stack::ret(rt);
}
