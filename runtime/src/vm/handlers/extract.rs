use iced_x86::code_asm::{al, r12, r8, r8d, r9b, rax, rcx, xmm0, CodeLabel};

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMWidth,
        utils::{self, scratch},
    },
};

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut dword = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // al -> element
    utils::bytecode::read_byte(rt, rcx, al);
    // r9b -> lane
    utils::bytecode::read_byte(rt, rcx, r9b);

    // load xmm0
    scratch::load_128(rt, r12, xmm0);

    // cmp al, ...
    rt.asm
        .cmp(al, rt.mapper.index(VMWidth::Lower32) as i32)
        .unwrap();
    // je ...
    rt.asm.je(dword).unwrap();

    lane(rt, r9b, &mut epilogue, 8, |rt, lane| {
        // pextrw r8d, xmm0, ...
        rt.asm.pextrw(r8d, xmm0, lane).unwrap();
    });

    rt.asm.set_label(&mut dword).unwrap();
    {
        lane(rt, r9b, &mut epilogue, 4, |rt, lane| {
            // pextrd r8d, xmm0, ...
            rt.asm.pextrd(r8d, xmm0, lane).unwrap();
        });
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

fn lane(
    runtime: &mut Runtime,
    selector: iced_x86::code_asm::AsmRegister8,
    epilogue: &mut CodeLabel,
    count: u32,
    emit: impl Fn(&mut Runtime, u32),
) {
    for index in 0..count {
        let mut next = rt.asm.create_label();

        // cmp ..., ...
        rt.asm.cmp(selector, index as i32).unwrap();
        // jne ...
        rt.asm.jne(next).unwrap();

        emit(rt, index);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();

        rt.asm.set_label(&mut next).unwrap();
    }

    rt.asm.zero_bytes().unwrap();
}
