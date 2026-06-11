use iced_x86::code_asm::{al, r12, rax, rcx, xmm0, xmm1, ymm0, ymm1};

use crate::{
    runtime::Runtime,
    vm::utils::{self, scratch},
};

pub fn bitwise(
    rt: &mut Runtime,
    sse: impl FnOnce(&mut Runtime) + 'static,
    avx: impl FnOnce(&mut Runtime) + 'static,
) {
    let mut epilogue = rt.asm.create_label();

    // al -> width
    utils::bytecode::read_byte(rt, rcx, al);

    utils::width::dispatch(
        rt,
        al,
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
        Some(Box::new(|rt| {
            // load xmm1
            scratch::load_128(rt, r12, xmm1);
            // load xmm0
            scratch::load_128(rt, r12, xmm0);
            sse(rt);
            // store xmm0
            scratch::store_128(rt, r12, xmm0);
        })),
        Some(Box::new(|rt| {
            // load ymm1
            scratch::load_256(rt, r12, ymm1);
            // load ymm0
            scratch::load_256(rt, r12, ymm0);
            avx(rt);
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
