use iced_x86::code_asm::{r8, r8d, rax, rdx, xmm0};

use crate::{
    runtime::Runtime,
    vm::utils::{scratch, stack},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // load xmm0
    scratch::load_128(rt, xmm0);

    // pmovmskb r8d, xmm0
    rt.asm.pmovmskb(r8d, xmm0).unwrap();

    // store r8
    scratch::store(rt, r8);

    // mov rax, rdx
    rt.asm.mov(rax, rdx).unwrap();
    // ret
    stack::ret(rt);
}
