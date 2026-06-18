use crate::mba;

use iced_x86::{
    code_asm::{
        asm_traits::{CodeAsmAdd, CodeAsmSub},
        registers::*,
        AsmMemoryOperand, AsmRegister16, AsmRegister32, AsmRegister64, AsmRegister8, CodeAssembler,
    },
    IcedError, Register,
};

use rand::seq::IteratorRandom;
use std::ops::{Deref, DerefMut};

use crate::flags::junkify;

pub struct Emitter {
    inner: CodeAssembler,
}

impl Emitter {
    pub fn new(bitness: u32) -> Result<Self, IcedError> {
        Ok(Self {
            inner: CodeAssembler::new(bitness)?,
        })
    }
}

impl Deref for Emitter {
    type Target = CodeAssembler;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Emitter {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

pub trait FullRegister {
    fn full_register(self) -> Register;
}

impl<T: Into<Register>> FullRegister for T {
    fn full_register(self) -> Register {
        self.into().full_register()
    }
}

pub trait ToGpr64 {
    fn gpr64(self) -> AsmRegister64;
}

impl<T: Into<Register>> ToGpr64 for T {
    fn gpr64(self) -> AsmRegister64 {
        get_gpr64(self.into().full_register()).unwrap()
    }
}

pub trait ToGpr32 {
    fn gpr32(self) -> AsmRegister32;
}

impl<T: Into<Register>> ToGpr32 for T {
    fn gpr32(self) -> AsmRegister32 {
        get_gpr32(self.into().full_register32()).unwrap()
    }
}

pub trait ToGpr8Lo {
    fn gpr8lo(self) -> AsmRegister8;
}

impl<T: Into<Register>> ToGpr8Lo for T {
    fn gpr8lo(self) -> AsmRegister8 {
        match self.into().full_register() {
            Register::RAX => al,
            Register::RCX => cl,
            Register::RDX => dl,
            Register::RBX => bl,
            Register::RBP => bpl,
            Register::RSI => sil,
            Register::RDI => dil,
            Register::R8 => r8b,
            Register::R9 => r9b,
            Register::R10 => r10b,
            Register::R11 => r11b,
            Register::R12 => r12b,
            Register::R13 => r13b,
            Register::R14 => r14b,
            Register::R15 => r15b,
            _ => unreachable!(),
        }
    }
}

pub trait ToGpr8Hi {
    fn gpr8hi(self) -> AsmRegister8;
}

impl<T: Into<Register>> ToGpr8Hi for T {
    fn gpr8hi(self) -> AsmRegister8 {
        match self.into().full_register() {
            Register::RAX => ah,
            Register::RCX => ch,
            Register::RDX => dh,
            Register::RBX => bh,
            _ => unreachable!(),
        }
    }
}

pub trait Obfuscate<Dst: Copy>: Copy {
    fn add(self, dst: Dst, asm: &mut CodeAssembler) -> Result<(), IcedError>;
    fn sub(self, dst: Dst, asm: &mut CodeAssembler) -> Result<(), IcedError>;
}

fn scratch<T: Copy + Into<Register>>(candidates: &[T], exclude: &[Register]) -> T
where
    Register: From<T>,
{
    *candidates
        .iter()
        .filter(|&&a| {
            !exclude
                .iter()
                .any(|&b| a.full_register() == b.full_register())
        })
        .choose(&mut rand::thread_rng())
        .unwrap()
}

fn scratch64(exclude: &[Register]) -> AsmRegister64 {
    const CANDIDATES: [AsmRegister64; 15] = [
        rax, rbx, rcx, rdx, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15,
    ];
    scratch(&CANDIDATES, exclude)
}

fn scratch32(exclude: &[Register]) -> AsmRegister32 {
    const CANDIDATES: [AsmRegister32; 15] = [
        eax, ecx, edx, ebx, ebp, esi, edi, r8d, r9d, r10d, r11d, r12d, r13d, r14d, r15d,
    ];
    scratch(&CANDIDATES, exclude)
}

fn scratch16(exclude: &[Register]) -> AsmRegister16 {
    const CANDIDATES: [AsmRegister16; 15] = [
        ax, cx, dx, bx, bp, si, di, r8w, r9w, r10w, r11w, r12w, r13w, r14w, r15w,
    ];
    scratch(&CANDIDATES, exclude)
}

fn scratch8(exclude: &[Register]) -> AsmRegister8 {
    const CANDIDATES: [AsmRegister8; 15] = [
        al, cl, dl, bl, bpl, sil, dil, r8b, r9b, r10b, r11b, r12b, r13b, r14b, r15b,
    ];
    scratch(&CANDIDATES, exclude)
}

macro_rules! operation {
    ($asm:expr, $register:expr, $body:expr) => {{
        $asm.push($register.gpr64())?;
        $body?;
        $asm.pop($register.gpr64())
    }};
}

macro_rules! mov {
    ($asm:expr, $dst:expr, $src:expr, $tmp1:expr, $tmp2:expr, $tmp3:expr) => {{
        let mut rng = rand::thread_rng();
        let flags = junkify($asm, $tmp1, &mut rng)?;
        mba::mov($asm, $dst, $src, $tmp1, $tmp2, $tmp3, &flags, &mut rng)
    }};
}

macro_rules! add {
    ($asm:expr, $dst:expr, $src:expr, $tmp1:expr, $tmp2:expr) => {{
        let mut rng = rand::thread_rng();
        let flags = junkify($asm, $tmp1, &mut rng)?;
        mba::add($asm, $dst, $src, $tmp1, $tmp2, &flags, &mut rng)
    }};
}

macro_rules! sub {
    ($asm:expr, $dst:expr, $src:expr, $tmp1:expr, $tmp2:expr) => {{
        let mut rng = rand::thread_rng();
        let flags = junkify($asm, $tmp1, &mut rng)?;
        mba::sub($asm, $dst, $src, $tmp1, $tmp2, &flags, &mut rng)
    }};
}

macro_rules! passthrough {
    ($dst:ty, $src:ty) => {
        impl Obfuscate<$dst> for $src {
            fn add(self, dst: $dst, asm: &mut CodeAssembler) -> Result<(), IcedError> {
                asm.add(dst, self)
            }
            fn sub(self, dst: $dst, asm: &mut CodeAssembler) -> Result<(), IcedError> {
                asm.sub(dst, self)
            }
        }
    };
}

passthrough!(AsmRegister8, AsmMemoryOperand);
passthrough!(AsmRegister16, AsmMemoryOperand);
passthrough!(AsmRegister32, AsmMemoryOperand);
passthrough!(AsmRegister64, AsmMemoryOperand);
passthrough!(AsmMemoryOperand, AsmRegister8);
passthrough!(AsmMemoryOperand, AsmRegister16);
passthrough!(AsmMemoryOperand, AsmRegister32);
passthrough!(AsmMemoryOperand, AsmRegister64);
passthrough!(AsmMemoryOperand, i32);
passthrough!(AsmMemoryOperand, u32);

macro_rules! implementation {
    ($dst:ty, $scratch:expr, $tmp1:expr, $tmp2:expr, $cast:expr) => {
        impl Obfuscate<$dst> for $dst {
            fn add(self, dst: $dst, asm: &mut CodeAssembler) -> Result<(), IcedError> {
                if dst.full_register() == Register::RSP {
                    return asm.add(dst, self);
                }
                if dst.full_register() == Register::R10
                    || dst.full_register() == Register::R11
                    || self.full_register() == Register::R10
                    || self.full_register() == Register::R11
                {
                    return asm.add(dst, self);
                }
                add!(asm, dst, self, $tmp1, $tmp2)
            }
            fn sub(self, dst: $dst, asm: &mut CodeAssembler) -> Result<(), IcedError> {
                if dst.full_register() == Register::RSP {
                    return asm.sub(dst, self);
                }
                if dst.full_register() == Register::R10
                    || dst.full_register() == Register::R11
                    || self.full_register() == Register::R10
                    || self.full_register() == Register::R11
                {
                    return asm.sub(dst, self);
                }
                sub!(asm, dst, self, $tmp1, $tmp2)
            }
        }
        impl Obfuscate<$dst> for i32 {
            fn add(self, dst: $dst, asm: &mut CodeAssembler) -> Result<(), IcedError> {
                if dst.full_register() == Register::RSP {
                    return asm.add(dst, self);
                }
                if dst.full_register() == Register::R10 || dst.full_register() == Register::R11 {
                    return asm.add(dst, self);
                }
                let src = $scratch(&[dst.into(), $tmp1.into(), $tmp2.into()]);
                operation!(asm, src, {
                    operation!(asm, dst, { mov!(asm, src, $cast(self), dst, $tmp1, $tmp2) })?;

                    add!(asm, dst, src, $tmp1, $tmp2)
                })
            }
            fn sub(self, dst: $dst, asm: &mut CodeAssembler) -> Result<(), IcedError> {
                if dst.full_register() == Register::RSP {
                    return asm.sub(dst, self);
                }
                if dst.full_register() == Register::R10 || dst.full_register() == Register::R11 {
                    return asm.sub(dst, self);
                }
                let src = $scratch(&[dst.into(), $tmp1.into(), $tmp2.into()]);
                operation!(asm, src, {
                    operation!(asm, dst, { mov!(asm, src, $cast(self), dst, $tmp1, $tmp2) })?;

                    sub!(asm, dst, src, $tmp1, $tmp2)
                })
            }
        }
    };
}

implementation!(AsmRegister8, scratch8, r10b, r11b, |x| x);
implementation!(AsmRegister16, scratch16, r10w, r11w, |x| x);
implementation!(AsmRegister32, scratch32, r10d, r11d, |x| x);
implementation!(AsmRegister64, scratch64, r10, r11, |x| x as i64);

impl Emitter {
    #[inline(always)]
    pub fn add<Dst, Src>(&mut self, dst: Dst, src: Src) -> Result<(), IcedError>
    where
        Src: Obfuscate<Dst>,
        Dst: Copy,
    {
        src.add(dst, &mut self.inner)
    }

    #[inline(always)]
    pub fn sub<Dst, Src>(&mut self, dst: Dst, src: Src) -> Result<(), IcedError>
    where
        Src: Obfuscate<Dst>,
        Dst: Copy,
    {
        src.sub(dst, &mut self.inner)
    }
}

impl Emitter {
    #[inline(always)]
    pub fn _add<Dst, Src>(&mut self, dst: Dst, src: Src) -> Result<(), IcedError>
    where
        CodeAssembler: CodeAsmAdd<Dst, Src>,
    {
        self.inner.add(dst, src)
    }

    #[inline(always)]
    pub fn _sub<Dst, Src>(&mut self, dst: Dst, src: Src) -> Result<(), IcedError>
    where
        CodeAssembler: CodeAsmSub<Dst, Src>,
    {
        self.inner.sub(dst, src)
    }
}
