use crate::runtime::Runtime;
use crate::vm::stack;

use iced_x86::code_asm::{rax, rdx};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // mov rax, rdx
    rt.asm.mov(rax, rdx).unwrap();
    // ret
    stack::ret(rt);
}
