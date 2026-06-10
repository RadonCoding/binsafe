use iced_x86::code_asm::{al, ptr, r12, r8, r9, r9b, r9d, r9w, rax, rcx};

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
    // load r9
    scratch::load(rt, r12, r9);

    utils::width::dispatch_register(
        rt,
        al,
        &mut epilogue,
        |rt| {
            rt.asm.xchg(ptr(r8), r9).unwrap();
        },
        |rt| {
            rt.asm.xchg(ptr(r8), r9d).unwrap();
        },
        |rt| {
            rt.asm.xchg(ptr(r8), r9w).unwrap();
        },
        |rt| {
            rt.asm.xchg(ptr(r8), r9b).unwrap();
        },
        |rt| {
            rt.asm.xchg(ptr(r8), r9b).unwrap();
        },
        |rt| {
            rt.asm.xchg(ptr(r8), r9).unwrap();
        },
        |rt| {
            rt.asm.xchg(ptr(r8), r9d).unwrap();
        },
        |rt| {
            rt.asm.xchg(ptr(r8), r9w).unwrap();
        },
        |rt| {
            rt.asm.xchg(ptr(r8), r9b).unwrap();
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
}
