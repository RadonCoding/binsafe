use iced_x86::code_asm::{rax, rdx, xmm0, xmm1};

use crate::{
    runtime::Runtime,
    vm::utils::{scratch, stack},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // load xmm0
    scratch::load_128(rt, xmm0);
    // load xmm1
    scratch::load_128(rt, xmm1);

    // pcmpeqb xmm0, xmm1
    rt.asm.pcmpeqb(xmm0, xmm1).unwrap();

    // store xmm0
    scratch::store_128(rt, xmm0);

    // mov rax, rdx
    rt.asm.mov(rax, rdx).unwrap();
    // ret
    stack::ret(rt);
}
