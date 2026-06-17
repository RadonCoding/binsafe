use iced_x86::code_asm::{eax, r12, rax, rcx, xmm0, xmm1, ymm0, ymm1};

use crate::{
    runtime::Runtime,
    vm::utils::{self, scratch},
};

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // eax -> width
    utils::bytecode::read_byte_zx(rt, rcx, eax);

    utils::width::dispatch(
        rt,
        rax,
        &mut epilogue,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(Box::new(|rt| {
            // load xmm1
            scratch::load_128(rt, r12, xmm1);
            // load xmm0
            scratch::load_128(rt, r12, xmm0);
            // pcmpeqb xmm0, xmm1
            rt.asm.pcmpeqb(xmm0, xmm1).unwrap();
            // store xmm0
            scratch::store_128(rt, r12, xmm0);
        })),
        Some(Box::new(|rt| {
            // load ymm1
            scratch::load_256(rt, r12, ymm1);
            // load ymm0
            scratch::load_256(rt, r12, ymm0);
            // vpcmpeqb ymm0, ymm0, ymm1
            rt.asm.vpcmpeqb(ymm0, ymm0, ymm1).unwrap();
            // store ymm0
            scratch::store_256(rt, r12, ymm0);
        })),
    );

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, rcx
        rt.asm.mov(rax, rcx).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
