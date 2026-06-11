use iced_x86::code_asm::{al, ptr, r12, r8, r9, r9b, r9d, r9w, rax, rcx, xmm0, ymm0};

use crate::{
    runtime::Runtime,
    vm::utils::{self, scratch},
};

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // al -> width
    utils::bytecode::read_byte(rt, rcx, al);

    // load r8
    scratch::load(rt, r12, r8);

    utils::width::dispatch_register_or_vector(
        rt,
        al,
        &mut epilogue,
        |rt| {
            // load r9
            scratch::load(rt, r12, r9);
            // mov [r8], r9
            rt.asm.mov(ptr(r8), r9).unwrap();
        },
        |rt| {
            // load r9
            scratch::load(rt, r12, r9);
            // mov [r8], r9d
            rt.asm.mov(ptr(r8), r9d).unwrap();
        },
        |rt| {
            // load r9
            scratch::load(rt, r12, r9);
            // mov [r8], r9w
            rt.asm.mov(ptr(r8), r9w).unwrap();
        },
        |_| {},
        |rt| {
            // load r9
            scratch::load(rt, r12, r9);
            // mov [r8], r9b
            rt.asm.mov(ptr(r8), r9b).unwrap();
        },
        |_| {},
        |_| {},
        |_| {},
        |_| {},
        |rt| {
            // load xmm0
            scratch::load_128(rt, r12, xmm0);
            // movups [r8], xmm0
            rt.asm.movups(ptr(r8), xmm0).unwrap();
        },
        |rt| {
            // load ymm0
            scratch::load_256(rt, r12, ymm0);
            // vmovups [r8], ymm0
            rt.asm.vmovups(ptr(r8), ymm0).unwrap();
        },
    );

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, rcx
        rt.asm.mov(rax, rcx).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
