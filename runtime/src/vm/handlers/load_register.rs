use iced_x86::code_asm::{al, byte_ptr, dword_ptr, ptr, r8, r8d, r9, r9d, rax, rcx, rdx, word_ptr};

use crate::{
    runtime::Runtime,
    vm::utils::{self, scratch, stack},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // al -> width
    utils::bytecode::read_byte(rt, rdx, al);

    // r8d -> source
    utils::bytecode::read_byte_zx(rt, rdx, r8d);

    utils::width::dispatch_register(
        rt,
        al,
        &mut epilogue,
        |rt| {
            // mov r9, [rcx + r8*8]
            rt.asm.mov(r9, ptr(rcx + r8 * 8)).unwrap();
        },
        |rt| {
            // mov r9d, [rcx + r8*8]
            rt.asm.mov(r9d, ptr(rcx + r8 * 8)).unwrap();
        },
        |rt| {
            // movzx r9, [rcx + r8*8]
            rt.asm.movzx(r9, word_ptr(rcx + r8 * 8)).unwrap();
        },
        |rt| {
            // movzx r9, [rcx + r8*8 + 0x1]
            rt.asm.movzx(r9, byte_ptr(rcx + r8 * 8 + 0x1)).unwrap();
        },
        |rt| {
            // movzx r9, [rcx + r8*8]
            rt.asm.movzx(r9, byte_ptr(rcx + r8 * 8)).unwrap();
        },
        |rt| {
            // mov r9, [rcx + r8*8]
            rt.asm.mov(r9, ptr(rcx + r8 * 8)).unwrap();
        },
        |rt| {
            // movsxd r9, [rcx + r8*8]
            rt.asm.movsxd(r9, dword_ptr(rcx + r8 * 8)).unwrap();
        },
        |rt| {
            // movsx r9, [rcx + r8*8]
            rt.asm.movsx(r9, word_ptr(rcx + r8 * 8)).unwrap();
        },
        |rt| {
            // movsx r9, [rcx + r8*8]
            rt.asm.movsx(r9, byte_ptr(rcx + r8 * 8)).unwrap();
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
