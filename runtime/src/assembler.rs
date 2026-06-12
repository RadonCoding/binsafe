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

fn scratch64(exclude: &[Register]) -> AsmRegister64 {
    const CANDIDATES: [AsmRegister64; 14] = [
        rax, rbx, rcx, rdx, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15,
    ];
    *CANDIDATES
        .iter()
        .filter(|&&r| !exclude.contains(&r.into()))
        .choose(&mut rand::thread_rng())
        .unwrap()
}

fn scratch32(exclude: &[Register]) -> AsmRegister32 {
    const CANDIDATES: [AsmRegister32; 14] = [
        eax, ebx, ecx, edx, esi, edi, r8d, r9d, r10d, r11d, r12d, r13d, r14d, r15d,
    ];
    *CANDIDATES
        .iter()
        .filter(|&&r| !exclude.contains(&r.into()))
        .choose(&mut rand::thread_rng())
        .unwrap()
}

fn scratch16(exclude: &[Register]) -> AsmRegister16 {
    const CANDIDATES: [AsmRegister16; 14] = [
        ax, bx, cx, dx, si, di, r8w, r9w, r10w, r11w, r12w, r13w, r14w, r15w,
    ];
    *CANDIDATES
        .iter()
        .filter(|&&r| !exclude.contains(&r.into()))
        .choose(&mut rand::thread_rng())
        .unwrap()
}

fn scratch8(exclude: &[Register]) -> AsmRegister8 {
    const CANDIDATES: [AsmRegister8; 20] = [
        al, cl, dl, bl, ah, ch, dh, bh, spl, bpl, sil, dil, r8b, r9b, r10b, r11b, r12b, r13b, r14b,
        r15b,
    ];
    *CANDIDATES
        .iter()
        .filter(|&&r| !exclude.contains(&r.into()))
        .choose(&mut rand::thread_rng())
        .unwrap()
}

fn imm() -> i32 {
    rand::random::<i32>() & 0xF
}

macro_rules! operation {
    ($asm:expr, $tmp:expr, $body:expr) => {{
        use iced_x86::code_asm::ptr;

        $asm.sub(rsp, 8)?;
        $asm.mov(ptr(rsp), $tmp)?;

        $body?;

        $asm.mov($tmp, ptr(rsp))?;
        $asm.add(rsp, 8)
    }};
}

macro_rules! mba_add_reg {
    ($asm:expr, $dst:expr, $src:expr, $tmp:expr) => {{
        match rand::random::<u8>() % 3 {
            0 => {
                // a + b = (a & b) + (a | b)
                $asm.mov($tmp, $dst)?;
                $asm.and($dst, $src)?;
                $asm.or($tmp, $src)?;
                $asm.add($dst, $tmp)?;
            }
            1 => {
                // a + b = (a ^ b) + 2*(a & b)
                $asm.mov($tmp, $dst)?;
                $asm.and($tmp, $src)?;
                $asm.add($tmp, $tmp)?;
                $asm.xor($dst, $src)?;
                $asm.add($dst, $tmp)?;
            }
            _ => {
                // a + b = (a + b + k) - k
                let k = imm();
                $asm.mov($tmp, $dst)?;
                $asm.xor($tmp, $src)?;
                $asm.or($dst, $src)?;
                $asm.add($dst, $dst)?;
                $asm.sub($dst, $tmp)?;
                $asm.add($dst, k)?;
                $asm.sub($dst, k)?;
            }
        }
        Ok::<(), IcedError>(())
    }};
}

macro_rules! mba_sub_reg {
    ($asm:expr, $dst:expr, $src:expr, $tmp:expr) => {{
        match rand::random::<u8>() % 3 {
            0 => {
                // a - b = a + (~b + 1)
                $asm.mov($tmp, $src)?;
                $asm.not($tmp)?;
                $asm.add($tmp, 1)?;
                $asm.add($dst, $tmp)?;
            }
            1 => {
                // a - b = (a ^ b) - 2*(b & ~a)
                $asm.mov($tmp, $dst)?;
                $asm.not($tmp)?;
                $asm.and($tmp, $src)?;
                $asm.add($tmp, $tmp)?;
                $asm.xor($dst, $src)?;
                $asm.sub($dst, $tmp)?;
            }
            _ => {
                // a - b = ~(~a + b)
                $asm.mov($tmp, $dst)?;
                $asm.not($tmp)?;
                $asm.add($tmp, $src)?;
                $asm.not($tmp)?;
                $asm.mov($dst, $tmp)?;
            }
        }
        Ok::<(), IcedError>(())
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

passthrough!(AsmMemoryOperand, AsmRegister8);
passthrough!(AsmMemoryOperand, AsmRegister16);
passthrough!(AsmMemoryOperand, AsmRegister32);
passthrough!(AsmMemoryOperand, AsmRegister64);

trait Load<Dst> {
    fn load(self, asm: &mut CodeAssembler, dst: Dst) -> Result<(), IcedError>;
}

impl Load<AsmRegister64> for i32 {
    fn load(self, asm: &mut CodeAssembler, dst: AsmRegister64) -> Result<(), IcedError> {
        asm.mov(dst, self as i64)
    }
}
impl Load<AsmRegister32> for i32 {
    fn load(self, asm: &mut CodeAssembler, dst: AsmRegister32) -> Result<(), IcedError> {
        asm.mov(dst, self)
    }
}
impl Load<AsmRegister16> for i32 {
    fn load(self, asm: &mut CodeAssembler, dst: AsmRegister16) -> Result<(), IcedError> {
        asm.mov(dst, self)
    }
}
impl Load<AsmRegister8> for i32 {
    fn load(self, asm: &mut CodeAssembler, dst: AsmRegister8) -> Result<(), IcedError> {
        asm.mov(dst, self)
    }
}

macro_rules! impl_obfuscate {
    ($dst:ty, $scratch:expr, $add:ident, $sub:ident) => {
        impl Obfuscate<$dst> for $dst {
            fn add(self, dst: $dst, asm: &mut CodeAssembler) -> Result<(), IcedError> {
                let tmp = $scratch(&[dst.into(), self.into()]);
                operation!(asm, tmp, { $add!(asm, dst, self, tmp) })
            }
            fn sub(self, dst: $dst, asm: &mut CodeAssembler) -> Result<(), IcedError> {
                let tmp = $scratch(&[dst.into(), self.into()]);
                operation!(asm, tmp, { $sub!(asm, dst, self, tmp) })
            }
        }
        impl Obfuscate<$dst> for i32 {
            fn add(self, dst: $dst, asm: &mut CodeAssembler) -> Result<(), IcedError> {
                let tmp = $scratch(&[dst.into()]);
                operation!(asm, tmp, {
                    self.load(asm, tmp)?;
                    $add!(asm, dst, tmp, tmp)
                })
            }
            fn sub(self, dst: $dst, asm: &mut CodeAssembler) -> Result<(), IcedError> {
                let tmp = $scratch(&[dst.into()]);
                operation!(asm, tmp, {
                    self.load(asm, tmp)?;
                    $sub!(asm, dst, tmp, tmp)
                })
            }
        }
    };
}

impl_obfuscate!(AsmRegister64, scratch64, mba_add_reg, mba_sub_reg);
impl_obfuscate!(AsmRegister32, scratch32, mba_add_reg, mba_sub_reg);
impl_obfuscate!(AsmRegister16, scratch16, mba_add_reg, mba_sub_reg);
impl_obfuscate!(AsmRegister8, scratch8, mba_add_reg, mba_sub_reg);
