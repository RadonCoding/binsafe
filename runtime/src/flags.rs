use crate::emitter::{ToGpr32, ToGpr64, ToGpr8Lo};
use iced_x86::{
    code_asm::{
        asm_traits::{CodeAsmAnd, CodeAsmNeg},
        CodeAssembler,
    },
    IcedError, Register,
};
use rand::Rng;

#[derive(Clone, Copy, Default)]
pub struct KFlags {
    pub cf: Option<bool>,
    pub zf: Option<bool>,
    pub sf: Option<bool>,
    pub of: Option<bool>,
    pub pf: Option<bool>,
}

fn parity(v: u64) -> bool {
    (v as u8).count_ones() % 2 == 0
}

pub fn junkify<T: Copy + Into<Register>>(
    asm: &mut CodeAssembler,
    r: T,
    rng: &mut impl Rng,
) -> Result<KFlags, IcedError> {
    asm.xor(r.gpr32(), r.gpr32())?;

    let mut flags = KFlags {
        cf: Some(false),
        zf: Some(true),
        sf: Some(false),
        of: Some(false),
        pf: Some(true),
    };

    let initial = rng.gen::<u64>();
    asm.mov(r.gpr64(), initial as i64)?;

    let mut value = initial;
    let depth = rng.gen_range(1u8..=3);

    for _ in 0..depth {
        match rng.gen_range(0u8..8) {
            0 => {
                let imm = (rng.gen::<u32>() as i32 as i64) as u64;
                asm.add(r.gpr64(), imm as i32)?;
                let (r, c) = value.overflowing_add(imm);
                let (_, o) = (value as i64).overflowing_add(imm as i64);
                flags.cf = Some(c);
                flags.zf = Some(r == 0);
                flags.sf = Some(r >> 63 == 1);
                flags.of = Some(o);
                flags.pf = Some(parity(r));
                value = r;
            }
            1 => {
                let imm = (rng.gen::<u32>() as i32 as i64) as u64;
                asm.sub(r.gpr64(), imm as i32)?;
                let (r, c) = value.overflowing_sub(imm);
                let (_, o) = (value as i64).overflowing_sub(imm as i64);
                flags.cf = Some(c);
                flags.zf = Some(r == 0);
                flags.sf = Some(r >> 63 == 1);
                flags.of = Some(o);
                flags.pf = Some(parity(r));
                value = r;
            }
            2 => {
                let imm = (rng.gen::<u32>() as i32 as i64) as u64;
                asm.and(r.gpr64(), imm as i32)?;
                let r = value & imm;
                flags.cf = Some(false);
                flags.of = Some(false);
                flags.zf = Some(r == 0);
                flags.sf = Some(r >> 63 == 1);
                flags.pf = Some(parity(r));
                value = r;
            }
            3 => {
                let imm = (rng.gen::<u32>() as i32 as i64) as u64;
                asm.or(r.gpr64(), imm as i32)?;
                let r = value | imm;
                flags.cf = Some(false);
                flags.of = Some(false);
                flags.zf = Some(r == 0);
                flags.sf = Some(r >> 63 == 1);
                flags.pf = Some(parity(r));
                value = r;
            }
            4 => {
                let imm = (rng.gen::<u32>() as i32 as i64) as u64;
                asm.xor(r.gpr64(), imm as i32)?;
                let r = value ^ imm;
                flags.cf = Some(false);
                flags.of = Some(false);
                flags.zf = Some(r == 0);
                flags.sf = Some(r >> 63 == 1);
                flags.pf = Some(parity(r));
                value = r;
            }
            5 => {
                asm.inc(r.gpr64())?;
                let (r, o) = (value as i64).overflowing_add(1);
                let r = r as u64;
                flags.zf = Some(r == 0);
                flags.sf = Some(r >> 63 == 1);
                flags.of = Some(o);
                flags.pf = Some(parity(r));
                value = r;
            }
            6 => {
                asm.dec(r.gpr64())?;
                let (r, o) = (value as i64).overflowing_sub(1);
                let r = r as u64;
                flags.zf = Some(r == 0);
                flags.sf = Some(r >> 63 == 1);
                flags.of = Some(o);
                flags.pf = Some(parity(r));
                value = r;
            }
            _ => {
                let shift = rng.gen_range(1u8..=6);
                asm.shl(r.gpr64(), shift as i32)?;
                let c = (value >> (64 - shift as u32)) & 1 == 1;
                let r = value.wrapping_shl(shift as u32);
                flags.cf = Some(c);
                flags.zf = Some(r == 0);
                flags.sf = Some(r >> 63 == 1);
                flags.pf = Some(parity(r));
                flags.of = if shift == 1 {
                    Some(c ^ (r >> 63 == 1))
                } else {
                    None
                };
                value = r;
            }
        }
    }

    Ok(flags)
}

pub fn materialize<T>(
    asm: &mut CodeAssembler,
    reg: T,
    flags: &KFlags,
    rng: &mut impl Rng,
) -> Result<u8, IcedError>
where
    T: Copy + Into<Register>,
    CodeAssembler: CodeAsmAnd<T, i32> + CodeAsmNeg<T>,
{
    let mut known = Vec::with_capacity(5);

    if let Some(v) = flags.cf {
        known.push((0u8, v));
    }
    if let Some(v) = flags.zf {
        known.push((1, v));
    }
    if let Some(v) = flags.sf {
        known.push((2, v));
    }
    if let Some(v) = flags.of {
        known.push((3, v));
    }
    if let Some(v) = flags.pf {
        known.push((4, v));
    }
    assert!(!known.is_empty());

    let (flag, set) = known[rng.gen_range(0..known.len())];

    let r8 = reg.gpr8lo();

    match flag {
        0 => asm.setb(r8)?,
        1 => asm.setz(r8)?,
        2 => asm.sets(r8)?,
        3 => asm.seto(r8)?,
        _ => asm.setp(r8)?,
    }

    asm.and(reg, 1i32)?;

    // reg ∈ {0, 1} ↦ neg(reg) ∈ {0, -1}
    asm.neg(reg)?;

    Ok(set as u8)
}
