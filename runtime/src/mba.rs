use std::ops::Sub;

use crate::emitter::{ToGpr32, ToGpr64, ToGpr8Lo};
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
    U: Copy
        + WrappingAdd
        + WrappingSub
        + From<u8>
        + PartialOrd
        + Sub<Output = U>
        + SampleUniform
        + Into<i64>
        + TryFrom<i64>,
    <U as TryFrom<i64>>::Error: std::fmt::Debug,
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
    let register = dst.into();

    let truncate = |value: U| -> U {
        let raw = value.into();

        let truncated = match register.size() {
            1 => (raw as i8) as i64,
            2 => (raw as i16) as i64,
            4 => (raw as i32) as i64,
            _ => raw,
        };
        U::try_from(truncated).unwrap()
    };

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

        asm.mov(dst, truncate(b))?;
        asm.mov(tmp1, truncate(a))?;
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

        asm.mov(dst, truncate(b))?;
        asm.mov(tmp1, truncate(a))?;
        sub(asm, dst, tmp1, tmp2, tmp3, flags, rng)?;
    }
    Ok(())
}

fn materialize<T>(
    asm: &mut CodeAssembler,
    tmp1: T,
    tmp2: T,
    flags: &KFlags,
    rng: &mut impl Rng,
) -> Result<u8, IcedError>
where
    T: Copy + ToGpr64 + ToGpr32 + ToGpr8Lo,
{
    let mut known = Vec::with_capacity(5);
    if let Some(v) = flags.cf {
        known.push((0, v as u8));
    }
    if let Some(v) = flags.pf {
        known.push((2, v as u8));
    }
    if let Some(v) = flags.zf {
        known.push((6, v as u8));
    }
    if let Some(v) = flags.sf {
        known.push((7, v as u8));
    }
    if let Some(v) = flags.of {
        known.push((11, v as u8));
    }
    assert!(known.len() >= 2);

    asm.pushfq()?;
    asm.pop(tmp2.gpr64())?;

    asm.xor(tmp1.gpr64(), tmp1.gpr64())?;

    for &(shift, _) in &known {
        asm.mov(tmp1.gpr64(), tmp2.gpr64())?;
        asm.shr(tmp1.gpr64(), shift as i32)?;
        asm.and(tmp1.gpr64(), 0x1)?;
        asm.add(tmp2.gpr64(), tmp1.gpr64())?;
    }

    let mut k = known[0].1;
    asm.mov(tmp1.gpr64(), tmp2.gpr64())?;
    asm.and(tmp1.gpr64(), 0x1)?;
    asm.mov(tmp2.gpr64(), tmp1.gpr64())?;

    for &(_, val) in &known[1..] {
        asm.shr(tmp1.gpr64(), 0x1)?;
        match rng.gen_range(0..2) {
            0 => {
                asm.xor(tmp2.gpr64(), tmp1.gpr64())?;
                k ^= val;
            }
            _ => {
                asm.add(tmp2.gpr64(), tmp1.gpr64())?;
                k = (k + val) & 1;
            }
        }
    }

    asm.and(tmp2.gpr64(), 0x1)?;
    Ok(k)
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
    T: Copy + ToGpr64 + ToGpr32 + ToGpr8Lo,
    CodeAssembler: CodeAsmMov<T, T>
        + CodeAsmNot<T>
        + CodeAsmNeg<T>
        + CodeAsmAnd<T, T>
        + CodeAsmOr<T, T>
        + CodeAsmXor<T, T>
        + CodeAsmAdd<T, T>
        + CodeAsmSub<T, T>
        + CodeAsmAnd<T, i32>,
{
    let k = materialize(asm, tmp1, tmp2, flags, rng)?;
    asm.and(tmp2, 0x1)?;
    asm.neg(tmp2)?;

    asm.mov(tmp1, dst)?;
    asm.and(tmp1, src)?;

    asm.and(tmp2, tmp1)?;

    asm.xor(dst, src)?;

    // x + y = (x ^ y) + 2 * (x & y)
    if k == 0 {
        asm.add(dst, tmp1)?;
        asm.add(dst, tmp1)?;
        asm.sub(dst, tmp2)?;
    //  x + y = (x ^ y) + (x & y) - (~k & (x & y))
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
    T: Copy + ToGpr64 + ToGpr32 + ToGpr8Lo,
    CodeAssembler: CodeAsmMov<T, T>
        + CodeAsmNot<T>
        + CodeAsmNeg<T>
        + CodeAsmAnd<T, T>
        + CodeAsmOr<T, T>
        + CodeAsmXor<T, T>
        + CodeAsmAdd<T, T>
        + CodeAsmSub<T, T>
        + CodeAsmAnd<T, i32>,
{
    let k = materialize(asm, tmp1, tmp2, flags, rng)?;
    asm.and(tmp2, 0x1)?;
    asm.neg(tmp2)?;

    asm.mov(tmp1, dst)?;
    asm.not(tmp1)?;
    asm.and(tmp1, src)?;

    asm.and(tmp2, tmp1)?;

    asm.xor(dst, src)?;

    // x - y = (x ^ y) - 2 * (~x & y)
    if k == 0 {
        asm.sub(dst, tmp1)?;
        asm.sub(dst, tmp1)?;
        asm.add(dst, tmp2)?;
    }
    // x - y = (x ^ y) - (~x & y) + (~k & (~x & y))
    else {
        asm.sub(dst, tmp1)?;
        asm.sub(dst, tmp2)?;
    }

    Ok(())
}
