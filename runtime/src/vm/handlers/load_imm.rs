use iced_x86::code_asm::{al, r8, r8d, rax, rdx};

use crate::{
    runtime::Runtime,
    vm::utils::{self, scratch, stack},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // al -> width
    utils::bytecode::read_byte(rt, rdx, al);

    utils::bits::dispatch(
        rt,
        al,
        &mut epilogue,
        |rt| {
            // r8 -> imm
            utils::bytecode::read_qword(rt, rdx, r8);
        },
        |rt| {
            // r8d -> imm
            utils::bytecode::read_dword(rt, rdx, r8d);
        },
        |rt| {
            // r8d -> imm
            utils::bytecode::read_word_zx(rt, rdx, r8d);
        },
        |rt| {
            // r8d -> imm
            utils::bytecode::read_byte_zx(rt, rdx, r8d);
        },
        |rt| {
            // r8d -> imm
            utils::bytecode::read_byte_zx(rt, rdx, r8d);
        },
    );

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // store r8
        scratch::store(rt, r8);

        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();
        // ret
        stack::ret(rt);
    }
}
