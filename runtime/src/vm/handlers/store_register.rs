use iced_x86::code_asm::{al, ptr, r8, r8d, r9, r9b, r9d, r9w, rax, r12, rcx};

use crate::{
    runtime::Runtime,
    vm::utils::{self, scratch},
};

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // al -> width
    utils::bytecode::read_byte(rt, rcx, al);

    // r8d -> destination
    utils::bytecode::read_byte_zx(rt, rcx, r8d);

    // load r9
    scratch::load(rt, r12, r9);

    utils::width::dispatch_register(
        rt,
        al,
        &mut epilogue,
        |rt| {
            // mov [r12 + r8*8], r9
            rt.asm.mov(ptr(r12 + r8 * 8), r9).unwrap();
        },
        |rt| {
            // mov [r12 + r8*8], r9
            rt.asm.mov(ptr(r12 + r8 * 8), r9).unwrap();
        },
        |rt| {
            // mov [r12 + r8*8], r9w
            rt.asm.mov(ptr(r12 + r8 * 8), r9w).unwrap();
        },
        |rt| {
            // mov [r12 + r8*8 + 0x1], r9b
            rt.asm.mov(ptr(r12 + r8 * 8 + 0x1), r9b).unwrap();
        },
        |rt| {
            // mov [r12 + r8*8], r9b
            rt.asm.mov(ptr(r12 + r8 * 8), r9b).unwrap();
        },
        |rt| {
            // mov [r12 + r8*8], r9
            rt.asm.mov(ptr(r12 + r8 * 8), r9).unwrap();
        },
        |rt| {
            // mov [r12 + r8*8], r9d
            rt.asm.mov(ptr(r12 + r8 * 8), r9d).unwrap();
        },
        |rt| {
            // mov [r12 + r8*8], r9w
            rt.asm.mov(ptr(r12 + r8 * 8), r9w).unwrap();
        },
        |rt| {
            // mov [r12 + r8*8], r9b
            rt.asm.mov(ptr(r12 + r8 * 8), r9b).unwrap();
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
