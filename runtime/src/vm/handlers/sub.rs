use iced_x86::code_asm::{al, r8, r8b, r8d, r8w, r9, r9b, r9d, r9w, rax, rcx, rdx};

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMReg,
        utils::{self, scratch, stack},
    },
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
            // sub r8, r9
            rt.asm.sub(r8, r9).unwrap();
        },
        |rt| {
            // sub r8d, r9d
            rt.asm.sub(r8d, r9d).unwrap();
        },
        |rt| {
            // sub r8w, r9w
            rt.asm.sub(r8w, r9w).unwrap();
        },
        |rt| {
            // sub r8b, r9b
            rt.asm.sub(r8b, r9b).unwrap();
        },
        |rt| {
            // sub r8b, r9b
            rt.asm.sub(r8b, r9b).unwrap();
        },
    );

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // pushfq
        stack::pushfq(rt);
        // pop r9
        stack::pop(rt, r9);
        // mov [rcx + ...], r9d
        utils::vreg::store_reg32(rt, rcx, r9d, VMReg::Flags);

        // store r8
        scratch::store(rt, r8);

        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();
        // ret
        stack::ret(rt);
    }
}
