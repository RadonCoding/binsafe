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
    const CANDIDATES: [AsmRegister64; 15] = [
        rax, rbx, rcx, rdx, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15,
    ];
    *CANDIDATES
        .iter()
        .filter(|&&a| {
            !exclude
                .iter()
                .any(|&b| b.full_register() == Register::from(a).full_register())
        })
        .choose(&mut rand::thread_rng())
        .unwrap()
}

fn scratch32(exclude: &[Register]) -> AsmRegister32 {
    const CANDIDATES: [AsmRegister32; 15] = [
        eax, ecx, edx, ebx, ebp, esi, edi, r8d, r9d, r10d, r11d, r12d, r13d, r14d, r15d,
    ];
    *CANDIDATES
        .iter()
        .filter(|&&a| {
            !exclude
                .iter()
                .any(|&b| b.full_register() == Register::from(a).full_register())
        })
        .choose(&mut rand::thread_rng())
        .unwrap()
}

fn scratch16(exclude: &[Register]) -> AsmRegister16 {
    const CANDIDATES: [AsmRegister16; 15] = [
        ax, cx, dx, bx, bp, si, di, r8w, r9w, r10w, r11w, r12w, r13w, r14w, r15w,
    ];
    *CANDIDATES
        .iter()
        .filter(|&&a| {
            !exclude
                .iter()
                .any(|&b| b.full_register() == Register::from(a).full_register())
        })
        .choose(&mut rand::thread_rng())
        .unwrap()
}

fn scratch8(exclude: &[Register]) -> AsmRegister8 {
    const CANDIDATES: [AsmRegister8; 15] = [
        al, cl, dl, bl, bpl, sil, dil, r8b, r9b, r10b, r11b, r12b, r13b, r14b, r15b,
    ];
    *CANDIDATES
        .iter()
        .filter(|&&a| {
            !exclude
                .iter()
                .any(|&b| b.full_register() == Register::from(a).full_register())
        })
        .choose(&mut rand::thread_rng())
        .unwrap()
}

fn imm() -> i32 {
    rand::random::<i32>() & 0xF
}

macro_rules! operation {
    ($asm:expr, $tmp:expr, $body:expr) => {{
        let tmp = get_gpr64(Register::from($tmp).full_register()).unwrap();
        $asm.push(tmp)?;
        $body?;
        $asm.pop(tmp)
    }};
}

macro_rules! mba_add {
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

macro_rules! mba_sub {
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

trait Load<Dst> {
    fn signed(self, asm: &mut CodeAssembler, dst: Dst) -> Result<(), IcedError>;
    fn unsigned(self, asm: &mut CodeAssembler, dst: Dst) -> Result<(), IcedError>;
}

impl Load<AsmRegister64> for i32 {
    fn signed(self, asm: &mut CodeAssembler, dst: AsmRegister64) -> Result<(), IcedError> {
        asm.mov(dst, self as u64)
    }
    fn unsigned(self, asm: &mut CodeAssembler, dst: AsmRegister64) -> Result<(), IcedError> {
        asm.mov(dst, self as u64 as i64)
    }
}
impl Load<AsmRegister32> for i32 {
    fn signed(self, asm: &mut CodeAssembler, dst: AsmRegister32) -> Result<(), IcedError> {
        asm.mov(dst, self)
    }
    fn unsigned(self, asm: &mut CodeAssembler, dst: AsmRegister32) -> Result<(), IcedError> {
        asm.mov(dst, self as u32 as i32)
    }
}
impl Load<AsmRegister16> for i32 {
    fn signed(self, asm: &mut CodeAssembler, dst: AsmRegister16) -> Result<(), IcedError> {
        asm.mov(dst, self)
    }
    fn unsigned(self, asm: &mut CodeAssembler, dst: AsmRegister16) -> Result<(), IcedError> {
        asm.mov(dst, self as u32 as i32)
    }
}
impl Load<AsmRegister8> for i32 {
    fn signed(self, asm: &mut CodeAssembler, dst: AsmRegister8) -> Result<(), IcedError> {
        asm.mov(dst, self)
    }
    fn unsigned(self, asm: &mut CodeAssembler, dst: AsmRegister8) -> Result<(), IcedError> {
        asm.mov(dst, self as u32 as i32)
    }
}

macro_rules! implementation {
    ($dst:ty, $scratch:expr) => {
        impl Obfuscate<$dst> for $dst {
            fn add(self, dst: $dst, asm: &mut CodeAssembler) -> Result<(), IcedError> {
                let tmp = $scratch(&[dst.into(), self.into()]);
                operation!(asm, tmp, { mba_add!(asm, dst, self, tmp) })
            }
            fn sub(self, dst: $dst, asm: &mut CodeAssembler) -> Result<(), IcedError> {
                let tmp = $scratch(&[dst.into(), self.into()]);
                operation!(asm, tmp, { mba_sub!(asm, dst, self, tmp) })
            }
        }
        impl Obfuscate<$dst> for i32 {
            fn add(self, dst: $dst, asm: &mut CodeAssembler) -> Result<(), IcedError> {
                let src = $scratch(&[dst.into()]);
                let tmp = $scratch(&[dst.into(), src.into()]);
                operation!(asm, src, {
                    operation!(asm, tmp, {
                        self.unsigned(asm, src)?;
                        mba_add!(asm, dst, src, tmp)
                    })
                })
            }
            fn sub(self, dst: $dst, asm: &mut CodeAssembler) -> Result<(), IcedError> {
                let src = $scratch(&[dst.into()]);
                let tmp = $scratch(&[dst.into(), src.into()]);
                operation!(asm, src, {
                    operation!(asm, tmp, {
                        self.signed(asm, src)?;
                        mba_sub!(asm, dst, src, tmp)
                    })
                })
            }
        }
    };
}

implementation!(AsmRegister64, scratch64);
implementation!(AsmRegister32, scratch32);
implementation!(AsmRegister16, scratch16);
implementation!(AsmRegister8, scratch8);

impl Assembler {
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
