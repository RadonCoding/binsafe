use core::panic;

use iced_x86::{Instruction, Mnemonic, Register};

use crate::mapper::{mapped, Mapper};
use crate::vm::encoders::Encode;
use crate::vm::lifters::{add, cmp, jcc, lea, mov, sub};

mapped! {
    VMOp {
        Jcc,
        // Load
        LoadImmediate,
        LoadRegister,
        LoadMemory,
        LoadAddress,
        // Store
        StoreRegister,
        StoreMemory,
        // Arithmetic
        Add,
        Sub,
        // Stack
        Discard,
        // Nop
        Nop,
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VMFlag {
    Carry = 0,      // CF
    Parity = 2,     // PF
    Auxiliary = 4,  // AF
    Zero = 6,       // ZF
    Sign = 7,       // SF
    Trap = 8,       // TF
    Interrupt = 9,  // IF
    Direction = 10, // DF
    Overflow = 11,  // OF
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
        NEntry, // Native Entry
        NBranch, // Native Branch
        NExit, // Native Exit
        BPointer, // Block Pointer
        BLength, // Block Length
        VImage, // Image Base
        VKey, // System Key
        VScratch0, // Scratch 0
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
    VMWidth {
        Lower8,
        Higher8,
        Lower16,
        Lower32,
        Lower64,
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

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct VMMem {
    pub base: VMReg,
    pub index: VMReg,
    pub scale: u8,
    pub displacement: i32,
    pub segment: VMSeg,
}

impl Encode for VMMem {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
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

pub fn convert(instructions: &[Instruction]) -> Option<Vec<Box<dyn Encode>>> {
    let mut output: Vec<Box<dyn Encode>> = Vec::new();

    for instruction in instructions {
        let ops = match instruction.mnemonic() {
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
            | Mnemonic::Js => jcc::encode(instruction)?,
            Mnemonic::Add => add::encode(instruction)?,
            Mnemonic::Sub => sub::encode(instruction)?,
            Mnemonic::Cmp => cmp::encode(instruction)?,
            Mnemonic::Lea => lea::encode(instruction)?,
            Mnemonic::Mov => mov::encode(instruction)?,
            Mnemonic::Nop => continue,
            _ => return None,
        };

        output.extend(ops);
    }

    Some(output)
}

pub fn assemble(mapper: &mut Mapper, operations: &mut [Box<dyn Encode>]) -> Vec<u8> {
    let mut bytes = Vec::new();

    for operation in operations {
        bytes.extend(operation.encode(mapper));
    }
    bytes
}
