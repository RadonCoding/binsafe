use iced_x86::code_asm::{al, r12, r8, r8d, rax, rcx};

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMWidth,
        utils::{self, scratch},
    },
};

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut wide = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // al -> width
    utils::bytecode::read_byte(rt, rcx, al);

    // load r8
    scratch::load(rt, r12, r8);

    // cmp al, ...
    rt.asm
        .cmp(al, rt.mapper.index(VMWidth::Lower64) as i32)
        .unwrap();
    // je ...
    rt.asm.je(wide).unwrap();

    // bswap r8d
    rt.asm.bswap(r8d).unwrap();
    // jmp ...
    rt.asm.jmp(epilogue).unwrap();

    rt.asm.set_label(&mut wide).unwrap();
    {
        // bswap r8
        rt.asm.bswap(r8).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // store r8
        scratch::store(rt, r12, r8);

        // mov rax, rcx
        rt.asm.mov(rax, rcx).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
