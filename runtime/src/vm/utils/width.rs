use iced_x86::code_asm::{AsmRegister8, CodeLabel};

use crate::{runtime::Runtime, vm::bytecode::VMWidth};

pub fn dispatch(
    rt: &mut Runtime,
    width: AsmRegister8,
    epilogue: &mut CodeLabel,
    lower64: impl FnOnce(&mut Runtime),
    lower32: impl FnOnce(&mut Runtime),
    lower16: impl FnOnce(&mut Runtime),
    higher8: impl FnOnce(&mut Runtime),
    lower8: impl FnOnce(&mut Runtime),
) {
    let mut l8 = rt.asm.create_label();
    let mut h8 = rt.asm.create_label();
    let mut l16 = rt.asm.create_label();
    let mut l32 = rt.asm.create_label();
    let mut l64 = rt.asm.create_label();

    // cmp width, ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Lower64) as i32)
        .unwrap();
    // je ...
    rt.asm.je(l64).unwrap();
    // cmp width, ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Lower32) as i32)
        .unwrap();
    // je ...
    rt.asm.je(l32).unwrap();
    // cmp width, ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Lower16) as i32)
        .unwrap();
    // je ...
    rt.asm.je(l16).unwrap();
    // cmp width, ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Higher8) as i32)
        .unwrap();
    // je ...
    rt.asm.je(h8).unwrap();

    rt.asm.set_label(&mut l8).unwrap();
    {
        lower8(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut h8).unwrap();
    {
        higher8(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut l16).unwrap();
    {
        lower16(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut l32).unwrap();
    {
        lower32(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut l64).unwrap();
    {
        lower64(rt);
    }
}
