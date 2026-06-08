use iced_x86::code_asm::{al, ptr, r8, r9, r9b, r9d, r9w, rax, rcx, rdx, xmm0};

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMWidth,
        utils::{self, scratch, stack},
    },
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut vector = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // al -> width
    utils::bytecode::read_byte(rt, rdx, al);

    // load r8
    scratch::load(rt, rcx, r8);

    // cmp al, ...
    rt.asm
        .cmp(al, rt.mapper.index(VMWidth::Lower128) as i32)
        .unwrap();
    // je ...
    rt.asm.je(vector).unwrap();

    // load r9
    scratch::load(rt, rcx, r9);

    utils::width::dispatch_register(
        rt,
        al,
        &mut epilogue,
        |rt| {
            // mov [r8], r9
            rt.asm.mov(ptr(r8), r9).unwrap();
        },
        |rt| {
            // mov [r8], r9d
            rt.asm.mov(ptr(r8), r9d).unwrap();
        },
        |rt| {
            // mov [r8], r9w
            rt.asm.mov(ptr(r8), r9w).unwrap();
        },
        |rt| {
            // mov [r8], r9b
            rt.asm.mov(ptr(r8), r9b).unwrap();
        },
        |rt| {
            // mov [r8], r9b
            rt.asm.mov(ptr(r8), r9b).unwrap();
        },
        |rt| {
            // mov [r8], r9
            rt.asm.mov(ptr(r8), r9).unwrap();
        },
        |rt| {
            // mov [r8], r9d
            rt.asm.mov(ptr(r8), r9d).unwrap();
        },
        |rt| {
            // mov [r8], r9w
            rt.asm.mov(ptr(r8), r9w).unwrap();
        },
        |rt| {
            // mov [r8], r9b
            rt.asm.mov(ptr(r8), r9b).unwrap();
        },
    );

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();
        // ret
        stack::ret(rt);
    }

    rt.asm.set_label(&mut vector).unwrap();
    {
        // load xmm0
        scratch::load_128(rt, rcx, xmm0);
        // movups [r8], xmm0
        rt.asm.movups(ptr(r8), xmm0).unwrap();

        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();
        // ret
        stack::ret(rt);
    }
}
