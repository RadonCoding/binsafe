use iced_x86::code_asm::{
    al, byte_ptr, dword_ptr, ptr, r12, r8, r9, r9d, rax, rcx, word_ptr, xmm0, ymm0,
};

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

    utils::width::dispatch(
        rt,
        al,
        &mut epilogue,
        Some(Box::new(|rt| {
            // mov r9, [r8]
            rt.asm.mov(r9, ptr(r8)).unwrap();
            // store r9
            scratch::store(rt, r12, r9);
        })),
        Some(Box::new(|rt| {
            // mov r9d, [r8]
            rt.asm.mov(r9d, ptr(r8)).unwrap();
            // store r9
            scratch::store(rt, r12, r9);
        })),
        Some(Box::new(|rt| {
            // movzx r9, [r8]
            rt.asm.movzx(r9, word_ptr(r8)).unwrap();
            // store r9
            scratch::store(rt, r12, r9);
        })),
        Some(Box::new(|rt| {
            // movzx r9, [r8]
            rt.asm.movzx(r9, byte_ptr(r8)).unwrap();
            // store r9
            scratch::store(rt, r12, r9);
        })),
        Some(Box::new(|rt| {
            // movzx r9, [r8]
            rt.asm.movzx(r9, byte_ptr(r8)).unwrap();
            // store r9
            scratch::store(rt, r12, r9);
        })),
        Some(Box::new(|rt| {
            // mov r9, [r8]
            rt.asm.mov(r9, ptr(r8)).unwrap();
            // store r9
            scratch::store(rt, r12, r9);
        })),
        Some(Box::new(|rt| {
            // movsxd r9, [r8]
            rt.asm.movsxd(r9, dword_ptr(r8)).unwrap();
            // store r9
            scratch::store(rt, r12, r9);
        })),
        Some(Box::new(|rt| {
            // movsx r9, [r8]
            rt.asm.movsx(r9, word_ptr(r8)).unwrap();
            // store r9
            scratch::store(rt, r12, r9);
        })),
        Some(Box::new(|rt| {
            // movsx r9, [r8]
            rt.asm.movsx(r9, byte_ptr(r8)).unwrap();
            // store r9
            scratch::store(rt, r12, r9);
        })),
        Some(Box::new(|rt| {
            // movups xmm0, [r8]
            rt.asm.movups(xmm0, ptr(r8)).unwrap();
            // store xmm0
            scratch::store_128(rt, r12, xmm0);
        })),
        Some(Box::new(|rt| {
            // movups ymm0, [r8]
            rt.asm.vmovups(ymm0, ptr(r8)).unwrap();
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
