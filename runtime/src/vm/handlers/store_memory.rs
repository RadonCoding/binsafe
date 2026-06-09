use iced_x86::code_asm::{al, ptr, r8, r9, r9b, r9d, r9w, rax, rcx, rdx, xmm0, ymm0};

use crate::{
    runtime::Runtime,
    vm::utils::{self, scratch},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // al -> width
    utils::bytecode::read_byte(rt, rdx, al);

    // load r8
    scratch::load(rt, rcx, r8);

    utils::width::dispatch_size(
        rt,
        al,
        &mut epilogue,
        |rt| {
            // load ymm0
            scratch::load_256(rt, rcx, ymm0);
            // vmovups [r8], ymm0
            rt.asm.vmovups(ptr(r8), ymm0).unwrap();
        },
        |rt| {
            // load xmm0
            scratch::load_128(rt, rcx, xmm0);
            // movups [r8], xmm0
            rt.asm.movups(ptr(r8), xmm0).unwrap();
        },
        |rt| {
            // load r9
            scratch::load(rt, rcx, r9);
            // mov [r8], r9
            rt.asm.mov(ptr(r8), r9).unwrap();
        },
        |rt| {
            // load r9
            scratch::load(rt, rcx, r9);
            // mov [r8], r9d
            rt.asm.mov(ptr(r8), r9d).unwrap();
        },
        |rt| {
            // load r9
            scratch::load(rt, rcx, r9);
            // mov [r8], r9w
            rt.asm.mov(ptr(r8), r9w).unwrap();
        },
        |rt| {
            // load r9
            scratch::load(rt, rcx, r9);
            // mov [r8], r9b
            rt.asm.mov(ptr(r8), r9b).unwrap();
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
