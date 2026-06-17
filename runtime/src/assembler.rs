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

trait FullRegister {
    fn full_register(self) -> Register;
}

impl<T: Into<Register>> FullRegister for T {
    fn full_register(self) -> Register {
        self.into().full_register()
    }
}

trait Gpr64 {
    fn gpr64(self) -> AsmRegister64;
}

impl<T: Into<Register>> Gpr64 for T {
    fn gpr64(self) -> AsmRegister64 {
        get_gpr64(self.into().full_register()).unwrap()
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
                .any(|&b| b.full_register() == a.full_register())
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
    ($assembler:expr, $temporary:expr, $body:expr) => {{
        $assembler.push($temporary.gpr64())?;
        $body;
        $assembler.pop($temporary.gpr64())
    }};
}

macro_rules! initialize_temporary {
    ($assembler:expr, $temporary:expr, $value:expr, $mode_move:expr) => {
        if $mode_move {
            $assembler.mov($temporary, $value)?;
        } else {
            $assembler.xor($temporary, $temporary)?;
            $assembler.add($temporary, $value)?;
        }
    };
}

macro_rules! scale_by_two {
    ($assembler:expr, $temporary:expr, $mode_shift_left:expr) => {
        if $mode_shift_left {
            $assembler.shl($temporary, 1)?;
        } else {
            $assembler.add($temporary, $temporary)?;
        }
    };
}

macro_rules! lightweight_identity {
    ($assembler:expr, $register:expr, $mode_identity:expr) => {
        match $mode_identity {
            1 => $assembler.or($register, 0)?,
            2 => $assembler.xor($register, 0)?,
            3 => $assembler.add($register, 0)?,
            4 => $assembler.sub($register, 0)?,
            5 => $assembler.and($register, -1)?,
            6 => $assembler.test($register, $register)?,
            _ => {}
        }
    };
}

macro_rules! post_operation {
    ($assembler:expr, $destination:expr, $mode_post:expr) => {
        match $mode_post {
            0 => $assembler.and($destination, $destination)?,
            1 => $assembler.or($destination, $destination)?,
            _ => {}
        }
    };
}

macro_rules! add {
    ($assembler:expr, $destination:expr, $source:expr, $temporary:expr) => {{
        let mode_move = rand::random::<bool>();
        let mode_shift_left = rand::random::<bool>();
        let mode_formula = rand::random::<u8>() % 4;
        let mode_post = rand::random::<u8>() % 3;

        let identity_first = rand::random::<u8>() % 7;
        let identity_second = rand::random::<u8>() % 7;
        let identity_third = rand::random::<u8>() % 7;
        let identity_fourth = rand::random::<u8>() % 7;

        lightweight_identity!($assembler, $destination, identity_first);

        match mode_formula {
            0 => {
                // a + b = (a & b) + (a | b)
                operation!($assembler, $temporary, {
                    initialize_temporary!($assembler, $temporary, $destination, mode_move);
                    $assembler.and($temporary, $source)?;
                    lightweight_identity!($assembler, $temporary, identity_second);
                    $assembler.or($destination, $source)?;
                    $assembler.add($destination, $temporary)?;
                    lightweight_identity!($assembler, $temporary, identity_fourth)
                })?;
            }
            1 => {
                // a + b = (a ^ b) + 2*(a & b)
                operation!($assembler, $temporary, {
                    initialize_temporary!($assembler, $temporary, $destination, mode_move);
                    $assembler.and($temporary, $source)?;
                    scale_by_two!($assembler, $temporary, mode_shift_left);
                    lightweight_identity!($assembler, $temporary, identity_second);
                    $assembler.xor($destination, $source)?;
                    $assembler.add($destination, $temporary)?;
                    lightweight_identity!($assembler, $temporary, identity_fourth)
                })?;
            }
            2 => {
                // a + b = 2*(a | b) - (a ^ b)
                operation!($assembler, $temporary, {
                    initialize_temporary!($assembler, $temporary, $destination, mode_move);
                    $assembler.xor($temporary, $source)?;
                    lightweight_identity!($assembler, $temporary, identity_second);
                    $assembler.or($destination, $source)?;
                    scale_by_two!($assembler, $destination, mode_shift_left);
                    $assembler.sub($destination, $temporary)?;
                    lightweight_identity!($assembler, $temporary, identity_fourth)
                })?;
            }
            _ => {
                // a + b = a - ~b - 1
                operation!($assembler, $temporary, {
                    initialize_temporary!($assembler, $temporary, $source, mode_move);
                    $assembler.not($temporary)?;
                    lightweight_identity!($assembler, $temporary, identity_second);
                    $assembler.sub($destination, $temporary)?;
                    $assembler.sub($destination, 1)?;
                    lightweight_identity!($assembler, $temporary, identity_fourth)
                })?;
            }
        }

        lightweight_identity!($assembler, $destination, identity_third);
        post_operation!($assembler, $destination, mode_post);

        Ok(())
    }};
}

macro_rules! sub {
    ($assembler:expr, $destination:expr, $source:expr, $temporary:expr) => {{
        let mode_move = rand::random::<bool>();
        let mode_shift_left = rand::random::<bool>();
        let mode_formula = rand::random::<u8>() % 4;
        let mode_post = rand::random::<u8>() % 3;

        let identity_first = rand::random::<u8>() % 7;
        let identity_second = rand::random::<u8>() % 7;
        let identity_third = rand::random::<u8>() % 7;
        let identity_fourth = rand::random::<u8>() % 7;

        lightweight_identity!($assembler, $destination, identity_first);

        match mode_formula {
            0 => {
                // a - b = a + (~b + 1)
                operation!($assembler, $temporary, {
                    initialize_temporary!($assembler, $temporary, $source, mode_move);
                    $assembler.not($temporary)?;
                    $assembler.add($temporary, 1)?;
                    lightweight_identity!($assembler, $temporary, identity_second);
                    $assembler.add($destination, $temporary)?;
                    lightweight_identity!($assembler, $temporary, identity_fourth)
                })?;
            }
            1 => {
                // a - b = (a ^ b) - 2*(~a & b)
                operation!($assembler, $temporary, {
                    initialize_temporary!($assembler, $temporary, $destination, mode_move);
                    $assembler.not($temporary)?;
                    $assembler.and($temporary, $source)?;
                    scale_by_two!($assembler, $temporary, mode_shift_left);
                    lightweight_identity!($assembler, $temporary, identity_second);
                    $assembler.xor($destination, $source)?;
                    $assembler.sub($destination, $temporary)?;
                    lightweight_identity!($assembler, $temporary, identity_fourth)
                })?;
            }
            2 => {
                // a - b = 2*(a & ~b) - (a ^ b)
                operation!($assembler, $temporary, {
                    initialize_temporary!($assembler, $temporary, $destination, mode_move);
                    $assembler.and($temporary, $source)?;
                    $assembler.xor($temporary, $destination)?;
                    scale_by_two!($assembler, $temporary, mode_shift_left);
                    lightweight_identity!($assembler, $temporary, identity_second);
                    $assembler.xor($destination, $source)?;
                    $assembler.sub($temporary, $destination)?;
                    $assembler.mov($destination, $temporary)?;
                    lightweight_identity!($assembler, $temporary, identity_fourth)
                })?;
            }
            _ => {
                // a - b = (a | ~b) - (~a | b)
                operation!($assembler, $temporary, {
                    initialize_temporary!($assembler, $temporary, $source, mode_move);
                    $assembler.not($temporary)?;
                    $assembler.or($temporary, $destination)?;
                    $assembler.not($destination)?;
                    lightweight_identity!($assembler, $temporary, identity_second);
                    $assembler.or($destination, $source)?;
                    $assembler.sub($temporary, $destination)?;
                    $assembler.mov($destination, $temporary)?;
                    lightweight_identity!($assembler, $temporary, identity_fourth)
                })?;
            }
        }

        lightweight_identity!($assembler, $destination, identity_third);
        post_operation!($assembler, $destination, mode_post);

        Ok(())
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
                if dst.full_register() == Register::RSP {
                    return asm.add(dst, self);
                }
                let tmp = $scratch(&[dst.into(), self.into()]);
                operation!(asm, tmp, { add!(asm, dst, self, tmp)? })
            }
            fn sub(self, dst: $dst, asm: &mut CodeAssembler) -> Result<(), IcedError> {
                if dst.full_register() == Register::RSP {
                    return asm.sub(dst, self);
                }
                let tmp = $scratch(&[dst.into(), self.into()]);
                operation!(asm, tmp, { sub!(asm, dst, self, tmp)? })
            }
        }
        impl Obfuscate<$dst> for i32 {
            fn add(self, dst: $dst, asm: &mut CodeAssembler) -> Result<(), IcedError> {
                if dst.full_register() == Register::RSP {
                    return asm.add(dst, self);
                }
                let src = $scratch(&[dst.into()]);
                let tmp = $scratch(&[dst.into(), src.into()]);
                operation!(asm, src, {
                    operation!(asm, tmp, {
                        self.unsigned(asm, src)?;

                        add!(asm, dst, src, tmp)?
                    })?
                })
            }
            fn sub(self, dst: $dst, asm: &mut CodeAssembler) -> Result<(), IcedError> {
                if dst.full_register() == Register::RSP {
                    return asm.sub(dst, self);
                }
                let src = $scratch(&[dst.into()]);
                let tmp = $scratch(&[dst.into(), src.into()]);
                operation!(asm, src, {
                    operation!(asm, tmp, {
                        self.signed(asm, src)?;

                        sub!(asm, dst, src, tmp)?
                    })?
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
