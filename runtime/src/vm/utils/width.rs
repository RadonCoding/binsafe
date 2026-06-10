use iced_x86::code_asm::{r12, xmm0, xmm1, ymm0, ymm1, AsmRegister8, CodeLabel};

use crate::{
    runtime::Runtime,
    vm::{bytecode::VMWidth, utils::scratch},
};

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

pub fn dispatch_size(
    rt: &mut Runtime,
    width: AsmRegister8,
    epilogue: &mut CodeLabel,
    ymmword: impl FnOnce(&mut Runtime),
    xmmword: impl FnOnce(&mut Runtime),
    qword: impl FnOnce(&mut Runtime),
    dword: impl FnOnce(&mut Runtime),
    word: impl FnOnce(&mut Runtime),
    byte: impl FnOnce(&mut Runtime),
) {
    let mut b = rt.asm.create_label();
    let mut w = rt.asm.create_label();
    let mut d = rt.asm.create_label();
    let mut q = rt.asm.create_label();
    let mut x = rt.asm.create_label();
    let mut y = rt.asm.create_label();

    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Lower256) as i32)
        .unwrap();
    // je ...
    rt.asm.je(y).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Lower128) as i32)
        .unwrap();
    // je ...
    rt.asm.je(x).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Lower64) as i32)
        .unwrap();
    // je ...
    rt.asm.je(q).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Lower32) as i32)
        .unwrap();
    // je ...
    rt.asm.je(d).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Lower16) as i32)
        .unwrap();
    // je ...
    rt.asm.je(w).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::Higher8) as i32)
        .unwrap();
    // je ...
    rt.asm.je(b).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::SLower64) as i32)
        .unwrap();
    // je ...
    rt.asm.je(q).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::SLower32) as i32)
        .unwrap();
    // je ...
    rt.asm.je(d).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::SLower16) as i32)
        .unwrap();
    // je ...
    rt.asm.je(w).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(width, rt.mapper.index(VMWidth::SLower8) as i32)
        .unwrap();
    // je ...
    rt.asm.je(b).unwrap();

    rt.asm.set_label(&mut b).unwrap();
    {
        byte(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut w).unwrap();
    {
        word(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut d).unwrap();
    {
        dword(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut q).unwrap();
    {
        qword(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut x).unwrap();
    {
        xmmword(rt);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut y).unwrap();
    {
        ymmword(rt);
    }
}

pub fn dispatch_lane_or_vector(
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

pub fn dispatch_float(
    rt: &mut Runtime,
    lane: AsmRegister8,
    vector: AsmRegister8,
    epilogue: &mut CodeLabel,
    scalar_single: impl FnOnce(&mut Runtime),
    scalar_double: impl FnOnce(&mut Runtime),
    packed_single: impl FnOnce(&mut Runtime),
    packed_double: impl FnOnce(&mut Runtime),
    wide_single: impl FnOnce(&mut Runtime),
    wide_double: impl FnOnce(&mut Runtime),
) {
    let mut double = rt.asm.create_label();
    let mut packed = rt.asm.create_label();
    let mut packed_d = rt.asm.create_label();
    let mut wide = rt.asm.create_label();
    let mut wide_d = rt.asm.create_label();

    // cmp ..., ...
    rt.asm
        .cmp(vector, rt.mapper.index(VMWidth::Lower256) as i32)
        .unwrap();
    // je ...
    rt.asm.je(wide).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(vector, rt.mapper.index(VMWidth::Lower128) as i32)
        .unwrap();
    // je ...
    rt.asm.je(packed).unwrap();
    // cmp ..., ...
    rt.asm
        .cmp(vector, rt.mapper.index(VMWidth::Lower64) as i32)
        .unwrap();
    // je ...
    rt.asm.je(double).unwrap();

    scratch::load_128(rt, r12, xmm1);
    scratch::load_128(rt, r12, xmm0);
    scalar_single(rt);
    scratch::store_128(rt, r12, xmm0);
    // jmp ...
    rt.asm.jmp(*epilogue).unwrap();

    rt.asm.set_label(&mut double).unwrap();
    {
        scratch::load_128(rt, r12, xmm1);
        scratch::load_128(rt, r12, xmm0);
        scalar_double(rt);
        scratch::store_128(rt, r12, xmm0);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut packed).unwrap();
    {
        // cmp ..., ...
        rt.asm
            .cmp(lane, rt.mapper.index(VMWidth::Lower64) as i32)
            .unwrap();
        // je ...
        rt.asm.je(packed_d).unwrap();

        scratch::load_128(rt, r12, xmm1);
        scratch::load_128(rt, r12, xmm0);
        packed_single(rt);
        scratch::store_128(rt, r12, xmm0);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();

        rt.asm.set_label(&mut packed_d).unwrap();
        scratch::load_128(rt, r12, xmm1);
        scratch::load_128(rt, r12, xmm0);
        packed_double(rt);
        scratch::store_128(rt, r12, xmm0);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }

    rt.asm.set_label(&mut wide).unwrap();
    {
        // cmp ..., ...
        rt.asm
            .cmp(lane, rt.mapper.index(VMWidth::Lower64) as i32)
            .unwrap();
        // je ...
        rt.asm.je(wide_d).unwrap();

        scratch::load_256(rt, r12, ymm1);
        scratch::load_256(rt, r12, ymm0);
        wide_single(rt);
        scratch::store_256(rt, r12, ymm0);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();

        rt.asm.set_label(&mut wide_d).unwrap();
        scratch::load_256(rt, r12, ymm1);
        scratch::load_256(rt, r12, ymm0);
        wide_double(rt);
        scratch::store_256(rt, r12, ymm0);
        // jmp ...
        rt.asm.jmp(*epilogue).unwrap();
    }
}
