use iced_x86::code_asm::{AsmRegister8, CodeLabel};

use crate::{runtime::Runtime, vm::bytecode::VMWidth};

pub fn dispatch_register(
    rt: &mut Runtime,
    width: AsmRegister8,
    epilogue: &mut CodeLabel,
    lower64: impl FnOnce(&mut Runtime),
    lower32: impl FnOnce(&mut Runtime),
    lower16: impl FnOnce(&mut Runtime),
    higher8: impl FnOnce(&mut Runtime),
    lower8: impl FnOnce(&mut Runtime),
    slower64: impl FnOnce(&mut Runtime),
    slower32: impl FnOnce(&mut Runtime),
    slower16: impl FnOnce(&mut Runtime),
    slower8: impl FnOnce(&mut Runtime),
) {
    let mut l8 = rt.asm.create_label();
    let mut h8 = rt.asm.create_label();
    let mut l16 = rt.asm.create_label();
    let mut l32 = rt.asm.create_label();
    let mut l64 = rt.asm.create_label();
    let mut s8 = rt.asm.create_label();
    let mut s16 = rt.asm.create_label();
    let mut s32 = rt.asm.create_label();
    let mut s64 = rt.asm.create_label();

    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Lower64) as i32)
        .unwrap();
    // je ...
    rt.asm.je(l64).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Lower32) as i32)
        .unwrap();
    // je ...
    rt.asm.je(l32).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Lower16) as i32)
        .unwrap();
    // je ...
    rt.asm.je(l16).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Higher8) as i32)
        .unwrap();
    // je ...
    rt.asm.je(h8).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::SLower64) as i32)
        .unwrap();
    // je ...
    rt.asm.je(s64).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::SLower32) as i32)
        .unwrap();
    // je ...
    rt.asm.je(s32).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::SLower16) as i32)
        .unwrap();
    // je ...
    rt.asm.je(s16).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::SLower8) as i32)
        .unwrap();
    // je ...
    rt.asm.je(s8).unwrap();

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

    rt.asm.set_label(&mut s8).unwrap();
    {
        slower8(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut s16).unwrap();
    {
        slower16(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut s32).unwrap();
    {
        slower32(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut s64).unwrap();
    {
        slower64(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut l64).unwrap();
    {
        lower64(rt);
    }
}

pub fn dispatch_vector(
    rt: &mut Runtime,
    width: AsmRegister8,
    epilogue: &mut CodeLabel,
    lower128: impl FnOnce(&mut Runtime),
    lower256: impl FnOnce(&mut Runtime),
) {
    let mut l256 = rt.asm.create_label();

    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Lower256) as i32)
        .unwrap();
    // je ...
    rt.asm.je(l256).unwrap();

    {
        lower128(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut l256).unwrap();
    {
        lower256(rt);
    }
}

pub fn dispatch_register_or_vector(
    rt: &mut Runtime,
    width: AsmRegister8,
    epilogue: &mut CodeLabel,
    lower64: impl FnOnce(&mut Runtime),
    lower32: impl FnOnce(&mut Runtime),
    lower16: impl FnOnce(&mut Runtime),
    higher8: impl FnOnce(&mut Runtime),
    lower8: impl FnOnce(&mut Runtime),
    slower64: impl FnOnce(&mut Runtime),
    slower32: impl FnOnce(&mut Runtime),
    slower16: impl FnOnce(&mut Runtime),
    slower8: impl FnOnce(&mut Runtime),
    lower128: impl FnOnce(&mut Runtime),
    lower256: impl FnOnce(&mut Runtime),
) {
    let mut l8 = rt.asm.create_label();
    let mut h8 = rt.asm.create_label();
    let mut l16 = rt.asm.create_label();
    let mut l32 = rt.asm.create_label();
    let mut l64 = rt.asm.create_label();
    let mut s8 = rt.asm.create_label();
    let mut s16 = rt.asm.create_label();
    let mut s32 = rt.asm.create_label();
    let mut s64 = rt.asm.create_label();

    let mut l128 = rt.asm.create_label();
    let mut l256 = rt.asm.create_label();

    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Lower64) as i32)
        .unwrap();
    // je ...
    rt.asm.je(l64).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Lower32) as i32)
        .unwrap();
    // je ...
    rt.asm.je(l32).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Lower16) as i32)
        .unwrap();
    // je ...
    rt.asm.je(l16).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Higher8) as i32)
        .unwrap();
    // je ...
    rt.asm.je(h8).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::SLower64) as i32)
        .unwrap();
    // je ...
    rt.asm.je(s64).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::SLower32) as i32)
        .unwrap();
    // je ...
    rt.asm.je(s32).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::SLower16) as i32)
        .unwrap();
    // je ...
    rt.asm.je(s16).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::SLower8) as i32)
        .unwrap();
    // je ...
    rt.asm.je(s8).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Lower128) as i32)
        .unwrap();
    // je ...
    rt.asm.je(l128).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Lower256) as i32)
        .unwrap();
    // je ...
    rt.asm.je(l256).unwrap();

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

    rt.asm.set_label(&mut s8).unwrap();
    {
        slower8(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut s16).unwrap();
    {
        slower16(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut s32).unwrap();
    {
        slower32(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut s64).unwrap();
    {
        slower64(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut l64).unwrap();
    {
        lower64(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut l128).unwrap();
    {
        lower128(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut l256).unwrap();
    {
        lower256(rt);
    }
}

pub fn dispatch_scalar(
    rt: &mut Runtime,
    width: AsmRegister8,
    epilogue: &mut CodeLabel,
    lower32: impl FnOnce(&mut Runtime),
    lower64: impl FnOnce(&mut Runtime),
    lower128: impl FnOnce(&mut Runtime),
    lower256: impl FnOnce(&mut Runtime),
) {
    let mut l64 = rt.asm.create_label();
    let mut l128 = rt.asm.create_label();
    let mut l256 = rt.asm.create_label();

    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Lower256) as i32)
        .unwrap();
    // je ...
    rt.asm.je(l256).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Lower128) as i32)
        .unwrap();
    // je ...
    rt.asm.je(l128).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Lower64) as i32)
        .unwrap();
    // je ...
    rt.asm.je(l64).unwrap();

    lower32(rt);
    // jmp ...
    rt.asm.jmp(*epilogue).unwrap();

    rt.asm.set_label(&mut l64).unwrap();
    {
        lower64(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut l128).unwrap();
    {
        lower128(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut l256).unwrap();
    {
        lower256(rt);
    }
}
