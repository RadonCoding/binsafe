use iced_x86::code_asm::{al, rax, rcx, rdx, xmm0, xmm1, ymm0, ymm1};

use crate::{
    runtime::Runtime,
    vm::utils::{self, scratch},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // al -> width
    utils::bytecode::read_byte(rt, rdx, al);

    utils::width::dispatch_vector(
        rt,
        al,
        &mut epilogue,
        |rt| {
            // load xmm1
            scratch::load_128(rt, rcx, xmm1);
            // load xmm0
            scratch::load_128(rt, rcx, xmm0);
            // pcmpeqb xmm0, xmm1
            rt.asm.pcmpeqb(xmm0, xmm1).unwrap();
            // store xmm0
            scratch::store_128(rt, rcx, xmm0);
        },
        |rt| {
            // load ymm1
            scratch::load_256(rt, rcx, ymm1);
            // load ymm0
            scratch::load_256(rt, rcx, ymm0);
            // vpcmpeqb ymm0, ymm0, ymm1
            rt.asm.vpcmpeqb(ymm0, ymm0, ymm1).unwrap();
            // store ymm0
            scratch::store_256(rt, rcx, ymm0);
        },
    );

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
