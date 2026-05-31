use iced_x86::code_asm::{al, byte_ptr, dword_ptr, ptr, r8, r9, r9d, rax, rdx, word_ptr};

use crate::{
    runtime::Runtime,
    vm::utils::{self, scratch, stack},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // al -> width
    utils::bytecode::read_byte(rt, rdx, al);

    // load r8
    scratch::load(rt, r8);

    utils::width::dispatch(
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
        scratch::store(rt, r9);

        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();
        // ret
        stack::ret(rt);
    }
}
