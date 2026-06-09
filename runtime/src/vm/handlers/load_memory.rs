use iced_x86::code_asm::{
    al, byte_ptr, dword_ptr, ptr, r8, r9, r9d, rax, r12, rcx, word_ptr, xmm0,
};

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMWidth,
        utils::{self, scratch},
    },
};

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut vector = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // al -> width
    utils::bytecode::read_byte(rt, rcx, al);

    // load r8
    scratch::load(rt, r12, r8);

    // cmp al, ...
    rt.asm
        .cmp(al, rt.mapper.index(VMWidth::Lower128) as i32)
        .unwrap();
    // je ...
    rt.asm.je(vector).unwrap();

    utils::width::dispatch_register(
        rt,
        al,
        &mut epilogue,
        |rt| {
            // mov r9, [r8]
            rt.asm.mov(r9, ptr(r8)).unwrap();
        },
        |rt| {
            // mov r9d, [r8]
            rt.asm.mov(r9d, ptr(r8)).unwrap();
        },
        |rt| {
            // movzx r9, word ptr [r8]
            rt.asm.movzx(r9, word_ptr(r8)).unwrap();
        },
        |rt| {
            // movzx r9, byte ptr [r8]
            rt.asm.movzx(r9, byte_ptr(r8)).unwrap();
        },
        |rt| {
            // movzx r9, byte ptr [r8]
            rt.asm.movzx(r9, byte_ptr(r8)).unwrap();
        },
        |rt| {
            // mov r9, [r8]
            rt.asm.mov(r9, ptr(r8)).unwrap();
        },
        |rt| {
            // movsxd r9, dword ptr [r8]
            rt.asm.movsxd(r9, dword_ptr(r8)).unwrap();
        },
        |rt| {
            // movsx r9, word ptr [r8]
            rt.asm.movsx(r9, word_ptr(r8)).unwrap();
        },
        |rt| {
            // movsx r9, byte ptr [r8]
            rt.asm.movsx(r9, byte_ptr(r8)).unwrap();
        },
    );

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // store r9
        scratch::store(rt, r12, r9);

        // mov rax, rcx
        rt.asm.mov(rax, rcx).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }

    rt.asm.set_label(&mut vector).unwrap();
    {
        // movups xmm0, [r8]
        rt.asm.movups(xmm0, ptr(r8)).unwrap();
        // store xmm0
        scratch::store_128(rt, r12, xmm0);

        // mov rax, rcx
        rt.asm.mov(rax, rcx).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
