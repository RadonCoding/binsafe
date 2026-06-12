use iced_x86::{
    code_asm::{
        registers::*, AsmMemoryOperand, AsmRegister16, AsmRegister32, AsmRegister64, AsmRegister8,
        CodeAssembler,
    },
    IcedError, Register,
};
use rand::seq::IteratorRandom;
use std::ops::{Deref, DerefMut};

pub struct Assembler {
    inner: CodeAssembler,
}

impl Assembler {
    pub fn new(bitness: u32) -> Result<Self, IcedError> {
        Ok(Self {
            inner: CodeAssembler::new(bitness)?,
        })
    }
}

impl Deref for Assembler {
    type Target = CodeAssembler;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Assembler {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

pub trait Obfuscate<Dst: Copy>: Copy {
    fn add(self, dst: Dst, asm: &mut CodeAssembler) -> Result<(), IcedError>;
    fn sub(self, dst: Dst, asm: &mut CodeAssembler) -> Result<(), IcedError>;
}

macro_rules! mbaadd {
    ($asm:expr, $dst:expr, $src:expr, $tmp:expr) => {{
        $asm.push($tmp)?;
        let result = match rand::random::<u8>() % 3 {
            // a + b = (a | b) + (a & b)
            0 => {
                $asm.mov($tmp, $dst)?;
                $asm.and($dst, $src)?;
                $asm.or($tmp, $src)?;
                $asm.add($dst, $tmp)?;
                Ok(())
            }
            // a + b = (a ^ b) + 2*(a & b)
            1 => {
                $asm.mov($tmp, $dst)?;
                $asm.and($tmp, $src)?;
                $asm.add($tmp, $tmp)?;
                $asm.xor($dst, $src)?;
                $asm.add($dst, $tmp)?;
                Ok(())
            }
            // a + b = 2*(a | b) - (a ^ b)
            _ => {
                $asm.mov($tmp, $dst)?;
                $asm.xor($tmp, $src)?;
                $asm.or($dst, $src)?;
                $asm.add($dst, $dst)?;
                $asm.sub($dst, $tmp)?;
                Ok(())
            }
        };
        $asm.pop($tmp)?;
        result
    }};
}

macro_rules! mbasub {
    ($asm:expr, $dst:expr, $src:expr, $tmp:expr) => {{
        $asm.push($tmp)?;
        let result = match rand::random::<u8>() % 3 {
            // a - b = a + (~b + 1)
            0 => {
                $asm.mov($tmp, $src)?;
                $asm.not($tmp)?;
                $asm.add($tmp, 1)?;
                $asm.add($dst, $tmp)?;
                Ok(())
            }
            // a - b = (a ^ b) - 2 * (b & ~a)
            1 => {
                $asm.mov($tmp, $dst)?;
                $asm.not($tmp)?;
                $asm.and($tmp, $src)?;
                $asm.add($tmp, $tmp)?;
                $asm.xor($dst, $src)?;
                $asm.sub($dst, $tmp)?;
                Ok(())
            }
            // a - b = ~(~a + b)
            _ => {
                $asm.mov($tmp, $dst)?;
                $asm.not($tmp)?;
                $asm.add($tmp, $src)?;
                $asm.not($tmp)?;
                $asm.mov($dst, $tmp)?;
                Ok(())
            }
        };
        $asm.pop($tmp)?;
        result
    }};
}

fn scratch(exclude: &[Register]) -> AsmRegister64 {
    const CANDIDATES: [AsmRegister64; 14] = [
        rax, rbx, rcx, rdx, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15,
    ];
    *CANDIDATES
        .iter()
        .filter(|&&r| !exclude.contains(&r.into()))
        .choose(&mut rand::thread_rng())
        .unwrap()
}

impl Obfuscate<AsmRegister64> for AsmRegister64 {
    fn add(self, dst: AsmRegister64, asm: &mut CodeAssembler) -> Result<(), IcedError> {
        let scratch = scratch(&[dst.into(), self.into()]);
        mbaadd!(asm, dst, self, scratch)
    }

    fn sub(self, dst: AsmRegister64, asm: &mut CodeAssembler) -> Result<(), IcedError> {
        let scratch = scratch(&[dst.into(), self.into()]);
        mbasub!(asm, dst, self, scratch)
    }
}

impl Obfuscate<AsmRegister64> for AsmMemoryOperand {
    fn add(self, dst: AsmRegister64, asm: &mut CodeAssembler) -> Result<(), IcedError> {
        asm.add(dst, self)
    }

    fn sub(self, dst: AsmRegister64, asm: &mut CodeAssembler) -> Result<(), IcedError> {
        asm.sub(dst, self)
    }
}

macro_rules! passthrough {
    ($dst:ty, $src:ty) => {
        impl Obfuscate<$dst> for $src {
            #[inline(always)]
            fn add(self, dst: $dst, asm: &mut CodeAssembler) -> Result<(), IcedError> {
                asm.add(dst, self)
            }

            #[inline(always)]
            fn sub(self, dst: $dst, asm: &mut CodeAssembler) -> Result<(), IcedError> {
                asm.sub(dst, self)
            }
        }
    };
}

passthrough!(AsmRegister8, i32);
passthrough!(AsmRegister8, u32);
passthrough!(AsmRegister8, AsmRegister8);
passthrough!(AsmMemoryOperand, AsmRegister8);

passthrough!(AsmRegister16, i32);
passthrough!(AsmRegister16, u32);
passthrough!(AsmRegister16, AsmRegister16);
passthrough!(AsmMemoryOperand, AsmRegister16);

passthrough!(AsmRegister32, i32);
passthrough!(AsmRegister32, u32);
passthrough!(AsmRegister32, AsmRegister32);
passthrough!(AsmMemoryOperand, AsmRegister32);

passthrough!(AsmRegister64, i32);

passthrough!(AsmMemoryOperand, AsmRegister64);
passthrough!(AsmMemoryOperand, i32);
passthrough!(AsmMemoryOperand, u32);

impl Assembler {
    pub fn add<Dst, Src>(&mut self, dst: Dst, src: Src) -> Result<(), IcedError>
    where
        Dst: Copy,
        Src: Obfuscate<Dst>,
    {
        src.add(dst, &mut self.inner)
    }

    pub fn sub<Dst, Src>(&mut self, dst: Dst, src: Src) -> Result<(), IcedError>
    where
        Dst: Copy,
        Src: Obfuscate<Dst>,
    {
        src.sub(dst, &mut self.inner)
    }
}
