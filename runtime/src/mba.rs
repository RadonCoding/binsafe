use std::ops::Sub;

use crate::flags;
use crate::flags::KFlags;
use iced_x86::{
    code_asm::{
        asm_traits::{
            CodeAsmAdd, CodeAsmAnd, CodeAsmMov, CodeAsmNeg, CodeAsmNot, CodeAsmOr, CodeAsmSub,
            CodeAsmXor,
        },
        CodeAssembler,
    },
    IcedError, Register,
};
use rand::distributions::uniform::SampleUniform;
use rand::Rng;

pub trait WrappingAdd {
    fn wrapping_add(self, rhs: Self) -> Self;
}
impl WrappingAdd for i32 {
    fn wrapping_add(self, rhs: Self) -> Self {
        i32::wrapping_add(self, rhs)
    }
}
impl WrappingAdd for i64 {
    fn wrapping_add(self, rhs: Self) -> Self {
        i64::wrapping_add(self, rhs)
    }
}

pub trait WrappingSub {
    fn wrapping_sub(self, rhs: Self) -> Self;
}
impl WrappingSub for i32 {
    fn wrapping_sub(self, rhs: Self) -> Self {
        i32::wrapping_sub(self, rhs)
    }
}
impl WrappingSub for i64 {
    fn wrapping_sub(self, rhs: Self) -> Self {
        i64::wrapping_sub(self, rhs)
    }
}

pub fn mov<T, U>(
    asm: &mut CodeAssembler,
    dst: T,
    src: U,
    tmp1: T,
    tmp2: T,
    tmp3: T,
    flags: &KFlags,
    rng: &mut impl Rng,
) -> Result<(), IcedError>
where
    T: Copy + Into<Register>,
    U: Copy + WrappingAdd + WrappingSub + From<u8> + PartialOrd + Sub<Output = U> + SampleUniform,
    CodeAssembler: CodeAsmMov<T, U>
        + CodeAsmMov<T, T>
        + CodeAsmNot<T>
        + CodeAsmNeg<T>
        + CodeAsmAnd<T, T>
        + CodeAsmOr<T, T>
        + CodeAsmXor<T, T>
        + CodeAsmAdd<T, T>
        + CodeAsmAdd<T, i32>
        + CodeAsmSub<T, T>
        + CodeAsmSub<T, i32>
        + CodeAsmAnd<T, i32>,
{
    if rng.gen::<bool>() {
        let zero = U::from(0u8);

        let (a, b) = if src >= zero {
            let a = rng.gen_range(zero..=src);
            let b = src.wrapping_sub(a);
            (a, b)
        } else {
            let a = rng.gen_range(src..=zero);
            let b = zero.wrapping_sub(src.wrapping_sub(a));
            (a, b)
        };
        asm.mov(dst, b)?;
        asm.mov(tmp1, a)?;
        add(asm, dst, tmp1, tmp2, tmp3, flags, rng)?;
    } else {
        let zero = U::from(0u8);

        let (a, b) = if src >= zero {
            let a = rng.gen_range(zero..=src);
            let b = src.wrapping_add(a);
            (a, b)
        } else {
            let a = rng.gen_range(src..=zero);
            let b = src.wrapping_sub(zero.wrapping_sub(a));
            (a, b)
        };
        asm.mov(dst, b)?;
        asm.mov(tmp1, a)?;
        sub(asm, dst, tmp1, tmp2, tmp3, flags, rng)?;
    }
    Ok(())
}

pub fn add<T>(
    asm: &mut CodeAssembler,
    dst: T,
    src: T,
    tmp1: T,
    tmp2: T,
    flags: &KFlags,
    rng: &mut impl Rng,
) -> Result<(), IcedError>
where
    T: Copy + Into<Register>,
    CodeAssembler: CodeAsmMov<T, T>
        + CodeAsmNot<T>
        + CodeAsmNeg<T>
        + CodeAsmAnd<T, T>
        + CodeAsmOr<T, T>
        + CodeAsmXor<T, T>
        + CodeAsmAdd<T, T>
        + CodeAsmAdd<T, i32>
        + CodeAsmSub<T, T>
        + CodeAsmSub<T, i32>
        + CodeAsmAnd<T, i32>,
{
    // tmp2 ∈ {0, -1}
    let k = flags::materialize(asm, tmp2, flags, rng)?;

    // tmp1 = x ∧ y
    asm.mov(tmp1, dst)?;
    asm.and(tmp1, src)?;

    // tmp2 = (x ∧ y) ∧ tmp2 (k)
    asm.and(tmp2, tmp1)?;

    // dst = x ⊕ y
    asm.xor(dst, src)?;

    if k == 0 {
        asm.add(dst, tmp1)?;
        asm.add(dst, tmp1)?;
        asm.sub(dst, tmp2)?;
    } else {
        asm.add(dst, tmp1)?;
        asm.add(dst, tmp2)?;
    }

    Ok(())
}

pub fn sub<T>(
    asm: &mut CodeAssembler,
    dst: T,
    src: T,
    tmp1: T,
    tmp2: T,
    flags: &KFlags,
    rng: &mut impl Rng,
) -> Result<(), IcedError>
where
    T: Copy + Into<Register>,
    CodeAssembler: CodeAsmMov<T, T>
        + CodeAsmNot<T>
        + CodeAsmNeg<T>
        + CodeAsmAnd<T, T>
        + CodeAsmOr<T, T>
        + CodeAsmXor<T, T>
        + CodeAsmAdd<T, T>
        + CodeAsmAdd<T, i32>
        + CodeAsmSub<T, T>
        + CodeAsmSub<T, i32>
        + CodeAsmAnd<T, i32>,
{
    // tmp2 ∈ {0, -1}
    let k = flags::materialize(asm, tmp2, flags, rng)?;

    // tmp1 = ¬x ∧ y
    asm.mov(tmp1, dst)?;
    asm.not(tmp1)?;
    asm.and(tmp1, src)?;

    // tmp2 = tmp1 ∧ tmp2 (k)
    asm.and(tmp2, tmp1)?;

    // dst = x ⊕ y
    asm.xor(dst, src)?;

    if k == 0 {
        asm.sub(dst, tmp1)?;
        asm.sub(dst, tmp1)?;
        asm.add(dst, tmp2)?;
    } else {
        asm.sub(dst, tmp1)?;
        asm.sub(dst, tmp2)?;
    }

    Ok(())
}
