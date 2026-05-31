use iced_x86::code_asm::{al, r8, r8b, r8d, r8w, r9, r9b, r9d, r9w, rax, rdx};

use crate::{
    runtime::{FnDef, Runtime},
    vm::utils::{self, scratch, stack},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // al -> width
    utils::bytecode::read_byte(rt, rdx, al);

    // load r9
    scratch::load(rt, r9);

    // load r8
    scratch::load(rt, r8);

    utils::width::dispatch(
        rt,
        al,
        &mut epilogue,
        |rt| {
            // xor r8, r9
            rt.asm.xor(r8, r9).unwrap();
        },
        |rt| {
            // xor r8d, r9d
            rt.asm.xor(r8d, r9d).unwrap();
        },
        |rt| {
            // xor r8w, r9w
            rt.asm.xor(r8w, r9w).unwrap();
        },
        |rt| {
            // xor r8b, r9b
            rt.asm.xor(r8b, r9b).unwrap();
        },
        |rt| {
            // xor r8b, r9b
            rt.asm.xor(r8b, r9b).unwrap();
        },
        |rt| {
            // xor r8d, r9d
            rt.asm.xor(r8d, r9d).unwrap();
        },
        |rt| {
            // xor r8w, r9w
            rt.asm.xor(r8w, r9w).unwrap();
        },
        |rt| {
            // xor r8b, r9b
            rt.asm.xor(r8b, r9b).unwrap();
        },
    );

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // pushfq
        stack::pushfq(rt);
        // pop rax
        stack::pop(rt, rax);
        // push rdx
        stack::push(rt, rdx);
        // mov rdx, rax
        rt.asm.mov(rdx, rax).unwrap();

        // store r8
        scratch::store(rt, r8);

        // call ...
        stack::call(rt, rt.func_labels[&FnDef::VmFlags]);

        // pop rax
        stack::pop(rt, rax);
        // ret
        stack::ret(rt);
    }
}
