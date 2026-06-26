use core::panic;
use std::any::Any;

use iced_x86::{Instruction, Mnemonic, Register};
use strum_macros::EnumIter;

use crate::mapper::{mapped, Mapper};
use crate::vm::encoders::Encode;
use crate::vm::lifters::{
    arithmetic, branch, bsr, bswap, bt, cmov, cmpxchg, div, extend, integer, lea, multiply,
    pcmpeqb, pmovskb, rdtsc, scalar, set, stack, transfer, tzcnt, xadd, xchg,
};
#[cfg(debug_assertions)]
use crate::vm::snapshot::Snapshots;
use crate::vm::transform::encrypt::Encrypt;
use crate::vm::transform::mutation::Mutation;
use crate::vm::transform::peephole::Peephole;
use crate::vm::transform::{permute, scramble, Transform};

mapped! {
    VMOp {
        Jcc,
        Ret,
        // Load
        LoadImmediate,
        LoadRegister,
        LoadMemory,
        LoadAddress,
        LoadVector,
        // Store
        StoreRegister,
        StoreMemory,
        StoreMerge,
        StoreExtend,
        // Arithmetic
        Add,
        Sub,
        And,
        Or,
        Xor,
        Rol,
        Ror,
        Shl,
        Shr,
        Sar,
        Mul,
        Div,
        TrailingZeros,
        BitScanReverse,
        ByteSwap,
        BitTest,
        BitTestSet,
        BitTestReset,
        BitTestComplement,
        // Stack
        Push,
        Pop,
        Discard,
        // Atomic
        Exchange,
        ExchangeAdd,
        CompareExchange,
        // Vector
        PackedByteMask,
        PackedByteEqual,
        VectorAnd,
        VectorAndNot,
        VectorOr,
        VectorXor,
        VectorAdd,
        VectorSub,
        VectorMul,
        VectorDiv,
        // Special
        Timestamp
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumIter)]
pub enum VMFlag {
    Carry = 0,      // CF
    Reserved1 = 1,  //
    Parity = 2,     // PF
    Auxiliary = 4,  // AF
    Zero = 6,       // ZF
    Sign = 7,       // SF
    Trap = 8,       // TF
    Interrupt = 9,  // IF
    Direction = 10, // DF
    Overflow = 11,  // OF
}

impl VMFlag {
    pub const fn bit32(self) -> u32 {
        1 << self as u32
    }

    pub const fn bit64(self) -> u64 {
        self.bit32() as u64
    }
}

mapped! {
    VMReg {
        None,

        Rax,
        Rcx,
        Rdx,
        Rbx,
        Rsp,
        Rbp,
        Rsi,
        Rdi,
        R8,
        R9,
        R10,
        R11,
        R12,
        R13,
        R14,
        R15,
        Flags,

        Vt0, // Current Timestamp
        Vt1, // Cached Timestamp

        Vg0, // General Purpose

        Vp0, // Persistent Purpose
        Vp1, // Persistent Purpose

        VShadow, // Shadow Context

        NEntry, // Native Entry
        NBranch, // Native Branch
        NExit, // Native Exit

        BPointer, // Block Pointer
        BLength, // Block Length
        BResume, // Block End

        VImage, // Image Base

        VImm, // Immediate Key

        VStack, // Virtual Stack
        VScratch, // Virtual Scratch
        VVector, // Virtual Vectors
    }
}

impl From<Register> for VMReg {
    fn from(reg: Register) -> Self {
        match reg {
            Register::None => Self::None,
            Register::RAX | Register::EAX | Register::AX | Register::AL | Register::AH => Self::Rax,
            Register::RCX | Register::ECX | Register::CX | Register::CL | Register::CH => Self::Rcx,
            Register::RDX | Register::EDX | Register::DX | Register::DL | Register::DH => Self::Rdx,
            Register::RBX | Register::EBX | Register::BX | Register::BL | Register::BH => Self::Rbx,
            Register::RSP | Register::ESP | Register::SP | Register::SPL => Self::Rsp,
            Register::RBP | Register::EBP | Register::BP | Register::BPL => Self::Rbp,
            Register::RSI | Register::ESI | Register::SI | Register::SIL => Self::Rsi,
            Register::RDI | Register::EDI | Register::DI | Register::DIL => Self::Rdi,
            Register::R8 | Register::R8D | Register::R8W | Register::R8L => Self::R8,
            Register::R9 | Register::R9D | Register::R9W | Register::R9L => Self::R9,
            Register::R10 | Register::R10D | Register::R10W | Register::R10L => Self::R10,
            Register::R11 | Register::R11D | Register::R11W | Register::R11L => Self::R11,
            Register::R12 | Register::R12D | Register::R12W | Register::R12L => Self::R12,
            Register::R13 | Register::R13D | Register::R13W | Register::R13L => Self::R13,
            Register::R14 | Register::R14D | Register::R14W | Register::R14L => Self::R14,
            Register::R15 | Register::R15D | Register::R15W | Register::R15L => Self::R15,
            Register::RIP => Self::VImage,
            _ => panic!("unsupported register: {reg:?}"),
        }
    }
}

mapped! {
    VMVec {
        Ymm0,
        Ymm1,
        Ymm2,
        Ymm3,
        Ymm4,
        Ymm5,
        Ymm6,
        Ymm7,
        Ymm8,
        Ymm9,
        Ymm10,
        Ymm11,
        Ymm12,
        Ymm13,
        Ymm14,
        Ymm15
    }
}

impl From<Register> for VMVec {
    fn from(reg: Register) -> Self {
        match reg {
            Register::XMM0 | Register::YMM0 => Self::Ymm0,
            Register::XMM1 | Register::YMM1 => Self::Ymm1,
            Register::XMM2 | Register::YMM2 => Self::Ymm2,
            Register::XMM3 | Register::YMM3 => Self::Ymm3,
            Register::XMM4 | Register::YMM4 => Self::Ymm4,
            Register::XMM5 | Register::YMM5 => Self::Ymm5,
            Register::XMM6 | Register::YMM6 => Self::Ymm6,
            Register::XMM7 | Register::YMM7 => Self::Ymm7,
            Register::XMM8 | Register::YMM8 => Self::Ymm8,
            Register::XMM9 | Register::YMM9 => Self::Ymm9,
            Register::XMM10 | Register::YMM10 => Self::Ymm10,
            Register::XMM11 | Register::YMM11 => Self::Ymm11,
            Register::XMM12 | Register::YMM12 => Self::Ymm12,
            Register::XMM13 | Register::YMM13 => Self::Ymm13,
            Register::XMM14 | Register::YMM14 => Self::Ymm14,
            Register::XMM15 | Register::YMM15 => Self::Ymm15,
            _ => panic!("unsupported register: {reg:?}"),
        }
    }
}

mapped! {
    VMPrecision {
        Integer,
        Float,
    }
}

mapped! {
    VMWidth {
        Lower8,
        Higher8,
        Lower16,
        Higher16,
        Lower32,
        Lower64,
        Lower128,
        Lower256,
        SLower8,
        SLower16,
        SLower32,
        SLower64,
    }
}

impl VMWidth {
    pub fn size(self) -> usize {
        match self {
            VMWidth::Lower8 | VMWidth::Higher8 | VMWidth::SLower8 => 1,
            VMWidth::Lower16 | VMWidth::Higher16 | VMWidth::SLower16 => 2,
            VMWidth::Lower32 | VMWidth::SLower32 => 4,
            VMWidth::Lower64 | VMWidth::SLower64 => 8,
            VMWidth::Lower128 => 16,
            VMWidth::Lower256 => 32,
        }
    }

    pub fn slots(self) -> i32 {
        (self.size() / 8).max(1) as i32
    }

    pub fn signed(self) -> Self {
        match self {
            VMWidth::Lower8 | VMWidth::Higher8 | VMWidth::SLower8 => VMWidth::SLower8,
            VMWidth::Lower16 | VMWidth::SLower16 => VMWidth::SLower16,
            VMWidth::Lower32 | VMWidth::SLower32 => VMWidth::SLower32,
            VMWidth::Lower64 | VMWidth::SLower64 => VMWidth::SLower64,
            other => other,
        }
    }
}

impl From<Register> for VMWidth {
    fn from(reg: Register) -> Self {
        match reg {
            reg if (reg >= Register::AL && reg <= Register::BL)
                || (reg >= Register::SPL && reg <= Register::R15L) =>
            {
                Self::Lower8
            }
            reg if (reg >= Register::AH && reg <= Register::BH) => Self::Higher8,
            reg if (reg >= Register::AX && reg <= Register::R15W) => Self::Lower16,
            reg if (reg >= Register::EAX && reg <= Register::R15D) || reg == Register::EIP => {
                Self::Lower32
            }
            reg if (reg >= Register::RAX && reg <= Register::R15) || reg == Register::RIP => {
                Self::Lower64
            }
            reg if reg >= Register::XMM0 && reg <= Register::XMM31 => Self::Lower128,
            reg if reg >= Register::YMM0 && reg <= Register::YMM31 => Self::Lower256,
            _ => panic!("unsupported register: {reg:?}"),
        }
    }
}

mapped! {
    VMSeg {
        None,
        Gs,
    }
}

impl From<Register> for VMSeg {
    fn from(reg: Register) -> Self {
        match reg {
            Register::None => Self::None,
            Register::GS => Self::Gs,
            _ => panic!("unsupported segment: {reg:?}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VMMem {
    pub base: VMReg,
    pub index: VMReg,
    pub scale: u8,
    pub displacement: i32,
    pub segment: VMSeg,
}

impl Encode for VMMem {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(mapper.index(self.base));
        bytes.push(mapper.index(self.index));
        bytes.push(self.scale);
        bytes.extend_from_slice(&self.displacement.to_le_bytes());
        bytes.push(mapper.index(self.segment));
        bytes
    }
}

impl From<&Instruction> for VMMem {
    fn from(instruction: &Instruction) -> Self {
        let base = VMReg::from(instruction.memory_base());
        let index = VMReg::from(instruction.memory_index());
        let scale = instruction.memory_index_scale() as u8;
        let displacement = (instruction.memory_displacement64() as i64)
            .try_into()
            .unwrap();
        let segment = VMSeg::from(instruction.segment_prefix());

        Self {
            base,
            index,
            scale,
            displacement,
            segment,
        }
    }
}

mapped! {
    VMTest {
        CMP,
        EQ,
        NEQ,
    }
}

mapped! {
    VMLogic {
        JAND, // JUMP AND
        JOR, // JUMP OR
        JXOR, // JUMP XOR

        CAND, // CALL AND
        COR,// CALL OR
        CXOR, // CALL XOR

        SAND, // SKIP AND
        SOR,  // SKIP OR
        SXOR, // SKIP XOR
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VMCondition {
    pub test: VMTest,
    pub lhs: u8,
    pub rhs: u8,
}

impl VMCondition {
    pub fn cmp(lhs: VMFlag, rhs: u8) -> VMCondition {
        VMCondition {
            test: VMTest::CMP,
            lhs: lhs as u8,
            rhs,
        }
    }

    pub fn eq(lhs: VMFlag, rhs: VMFlag) -> VMCondition {
        VMCondition {
            test: VMTest::EQ,
            lhs: lhs as u8,
            rhs: rhs as u8,
        }
    }

    pub fn neq(lhs: VMFlag, rhs: VMFlag) -> VMCondition {
        VMCondition {
            test: VMTest::NEQ,
            lhs: lhs as u8,
            rhs: rhs as u8,
        }
    }
}

impl Encode for VMCondition {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(self.test), self.lhs, self.rhs]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Lift,
    Mutation,
    Permute,
    Scramble,
    Encrypt,
    Peephole,
}

impl Phase {
    pub fn identifier(&self) -> &'static str {
        match self {
            Self::Lift => "lift",
            Self::Mutation => "mutation",
            Self::Permute => "permute",
            Self::Scramble => "scramble",
            Self::Encrypt => "encrypt",
            Self::Peephole => "peephole",
        }
    }
}

pub fn lift(mapper: &mut Mapper, instructions: &[Instruction]) -> Option<Vec<Box<dyn Encode>>> {
    let mut output: Vec<Box<dyn Encode>> = Vec::new();

    for instruction in instructions {
        let operations = match instruction.mnemonic() {
            Mnemonic::Ja
            | Mnemonic::Jae
            | Mnemonic::Jb
            | Mnemonic::Jbe
            | Mnemonic::Je
            | Mnemonic::Jg
            | Mnemonic::Jge
            | Mnemonic::Jl
            | Mnemonic::Jle
            | Mnemonic::Jne
            | Mnemonic::Jno
            | Mnemonic::Jnp
            | Mnemonic::Jns
            | Mnemonic::Jo
            | Mnemonic::Jp
            | Mnemonic::Js
            | Mnemonic::Jmp
            | Mnemonic::Call
            | Mnemonic::Ret => branch::encode(instruction)?,
            Mnemonic::Cmove
            | Mnemonic::Cmovne
            | Mnemonic::Cmova
            | Mnemonic::Cmovae
            | Mnemonic::Cmovb
            | Mnemonic::Cmovbe
            | Mnemonic::Cmovg
            | Mnemonic::Cmovge
            | Mnemonic::Cmovl
            | Mnemonic::Cmovle
            | Mnemonic::Cmovno
            | Mnemonic::Cmovnp
            | Mnemonic::Cmovns
            | Mnemonic::Cmovo
            | Mnemonic::Cmovp
            | Mnemonic::Cmovs => cmov::encode(mapper, instruction)?,
            Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::Adc
            | Mnemonic::Sbb
            | Mnemonic::Shl
            | Mnemonic::Shr
            | Mnemonic::Sar
            | Mnemonic::Rol
            | Mnemonic::Ror
            | Mnemonic::Cmp
            | Mnemonic::Test
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Xor
            | Mnemonic::Inc
            | Mnemonic::Dec
            | Mnemonic::Neg
            | Mnemonic::Not
            | Mnemonic::Pand
            | Mnemonic::Andps
            | Mnemonic::Andpd
            | Mnemonic::Vandps
            | Mnemonic::Por
            | Mnemonic::Orps
            | Mnemonic::Orpd
            | Mnemonic::Pxor
            | Mnemonic::Xorps
            | Mnemonic::Xorpd
            | Mnemonic::Vpxor
            | Mnemonic::Vxorps
            | Mnemonic::Pandn
            | Mnemonic::Andnps
            | Mnemonic::Andnpd
            | Mnemonic::Paddb
            | Mnemonic::Paddw
            | Mnemonic::Paddd
            | Mnemonic::Paddq
            | Mnemonic::Addps
            | Mnemonic::Addpd
            | Mnemonic::Vaddps
            | Mnemonic::Vaddpd
            | Mnemonic::Psubb
            | Mnemonic::Psubw
            | Mnemonic::Psubd
            | Mnemonic::Psubq
            | Mnemonic::Subps
            | Mnemonic::Subpd
            | Mnemonic::Vsubps
            | Mnemonic::Vsubpd
            | Mnemonic::Pmulld
            | Mnemonic::Vpmulld
            | Mnemonic::Pmullw
            | Mnemonic::Vpmullw
            | Mnemonic::Pmulhw
            | Mnemonic::Vpmulhw
            | Mnemonic::Mulps
            | Mnemonic::Vmulps
            | Mnemonic::Mulpd
            | Mnemonic::Vmulpd
            | Mnemonic::Divps
            | Mnemonic::Vdivps
            | Mnemonic::Divpd
            | Mnemonic::Vdivpd => arithmetic::encode(instruction)?,
            Mnemonic::Mul | Mnemonic::Imul => multiply::encode(instruction)?,
            Mnemonic::Div | Mnemonic::Idiv => div::encode(instruction)?,
            Mnemonic::Tzcnt => tzcnt::encode(instruction)?,
            Mnemonic::Bsr => bsr::encode(instruction)?,
            Mnemonic::Bswap => bswap::encode(instruction)?,
            Mnemonic::Bt | Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc => {
                bt::encode(instruction)?
            }
            Mnemonic::Xchg => xchg::encode(instruction)?,
            Mnemonic::Xadd => xadd::encode(instruction)?,
            Mnemonic::Cmpxchg => cmpxchg::encode(mapper, instruction)?,
            Mnemonic::Lea => lea::encode(instruction)?,
            Mnemonic::Mov
            | Mnemonic::Movaps
            | Mnemonic::Movups
            | Mnemonic::Movapd
            | Mnemonic::Movupd
            | Mnemonic::Movdqa
            | Mnemonic::Movdqu => transfer::encode(instruction)?,
            Mnemonic::Movd | Mnemonic::Movq => integer::encode(instruction)?,
            Mnemonic::Movss | Mnemonic::Movsd => scalar::encode(instruction)?,
            Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd => extend::encode(instruction)?,
            Mnemonic::Push | Mnemonic::Pop => stack::encode(instruction)?,
            Mnemonic::Pcmpeqb => pcmpeqb::encode(instruction)?,
            Mnemonic::Pmovmskb => pmovskb::encode(instruction)?,
            Mnemonic::Seta
            | Mnemonic::Setae
            | Mnemonic::Setb
            | Mnemonic::Setbe
            | Mnemonic::Sete
            | Mnemonic::Setg
            | Mnemonic::Setge
            | Mnemonic::Setl
            | Mnemonic::Setle
            | Mnemonic::Setne
            | Mnemonic::Setno
            | Mnemonic::Setnp
            | Mnemonic::Setns
            | Mnemonic::Seto
            | Mnemonic::Setp
            | Mnemonic::Sets => set::encode(mapper, instruction)?,
            Mnemonic::Rdtsc => rdtsc::encode(instruction)?,
            Mnemonic::Nop | Mnemonic::Int | Mnemonic::Int3 | Mnemonic::Ud2 | Mnemonic::Pause => {
                continue
            }
            _ => return None,
        };

        output.extend(operations);
    }

    Some(output)
}

pub fn assemble(mapper: &mut Mapper, operations: &[Box<dyn Encode>]) -> Vec<u8> {
    let mut bytes = Vec::new();

    for operation in operations {
        bytes.extend(operation.encode(mapper));
    }
    bytes
}

pub fn transform<F>(
    mapper: &mut Mapper,
    operations: Vec<Box<dyn Encode>>,
    mut picker: F,
) -> Vec<Box<dyn Encode>>
where
    F: FnMut(&[usize]) -> usize,
{
    let mut operations = operations;

    operations = Peephole.run(mapper, operations);
    operations = permute::permute(operations, &mut picker);
    operations = scramble::scramble(mapper, operations);
    operations = Mutation.run(mapper, operations);
    operations = Encrypt.run(mapper, operations);
    operations = permute::permute(operations, &mut picker);
    operations = Peephole.run(mapper, operations);

    operations
}

#[cfg(debug_assertions)]
pub fn transform_with_snapshots<F>(
    mapper: &mut Mapper,
    operations: Vec<Box<dyn Encode>>,
    mut picker: F,
) -> (Vec<Box<dyn Encode>>, Snapshots)
where
    F: FnMut(&[usize]) -> usize,
{
    let mut operations = operations;

    let mut snapshots = Snapshots::new();
    snapshots.record(Phase::Lift, &operations);

    operations = Peephole.run(mapper, operations);
    snapshots.record(Phase::Peephole, &operations);

    operations = permute::permute(operations, &mut picker);
    snapshots.record(Phase::Permute, &operations);

    operations = scramble::scramble(mapper, operations);
    snapshots.record(Phase::Scramble, &operations);

    operations = Mutation.run(mapper, operations);
    snapshots.record(Mutation.phase(), &operations);

    operations = Encrypt.run(mapper, operations);
    snapshots.record(Encrypt.phase(), &operations);

    operations = permute::permute(operations, &mut picker);
    snapshots.record(Phase::Permute, &operations);

    operations = Peephole.run(mapper, operations);
    snapshots.record(Phase::Peephole, &operations);

    (operations, snapshots)
}
