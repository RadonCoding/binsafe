use iced_x86::{Instruction, Mnemonic, OpKind, Register};

use crate::mapper::{mapped, Mapper};
use crate::vm::encoders::{arithmetic, branch, jcc, load, nop, stack, store, Encode};

mapped! {
    VMOp {
        PushPopRegs,
        PopRegs,
        PushImm,
        PushReg,
        PopReg,
        SetRegImm,
        SetRegReg,
        SetRegMem,
        SetMemImm,
        SetMemReg,
        AddSubRegImm,
        AddSubRegReg,
        AddSubRegMem,
        AddSubMemImm,
        AddSubMemReg,
        BranchImm,
        BranchReg,
        BranchMem,
        Jcc,
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
    VMTest {
        CMP,
        EQ,
        NEQ,
    }
}

mapped! {
    VMLogic {
        AND,
        OR,
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
        Ven, // Native Entry
        Vex, // Native Exit
        Vbp, // Block Pointer
        Vbl, // Block Length
        Vbr, // Virtual Branch
        Vib, // Image Base
        Vsk, // System Key
        Vs0, // Scratch 0
        Vs1, // Scratch 1
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
            Register::RIP => Self::Vib,
            _ => panic!("unsupported register: {reg:?}"),
        }
    }
}

mapped! {
    VMBits {
        Lower8,
        Higher8,
        Lower16,
        Lower32,
        Lower64,
    }
}

impl From<Register> for VMBits {
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

#[derive(Debug, Clone, Copy)]
pub struct VMMem {
    pub base: VMReg,
    pub index: VMReg,
    pub scale: u8,
    pub displacement: i32,
    pub seg: VMSeg,
}

impl Encode for VMMem {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(mapper.index(self.base));
        bytes.push(mapper.index(self.index));
        bytes.push(self.scale);
        bytes.extend_from_slice(&self.displacement.to_le_bytes());
        bytes.push(mapper.index(self.seg));
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
        let seg = VMSeg::from(instruction.segment_prefix());

        Self {
            base,
            index,
            scale,
            displacement,
            seg,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VMCond {
    pub cmp: VMTest,
    pub lhs: u8,
    pub rhs: u8,
}

impl Encode for VMCond {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(self.cmp), self.lhs, self.rhs]
    }
}

pub fn convert(mapper: &mut Mapper, instructions: &[Instruction]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;

    while i < instructions.len() {
        if let Some((bytes, consumed)) =
            stack::try_emit_push_pop_regs(mapper, &instructions[i..])
        {
            out.extend_from_slice(&bytes);
            i += consumed;
            continue;
        }

        let instruction = &instructions[i];

        let bytes = match instruction.mnemonic() {
            Mnemonic::Push | Mnemonic::Pop => stack::encode(mapper, instruction)?,
            Mnemonic::Mov => match instruction.op0_kind() {
                OpKind::Memory => store::encode(mapper, instruction)?,
                _ => load::encode(mapper, instruction)?,
            },
            Mnemonic::Lea => load::encode(mapper, instruction)?,
            Mnemonic::Add | Mnemonic::Sub | Mnemonic::Cmp => {
                arithmetic::encode(mapper, instruction)?
            }
            Mnemonic::Call | Mnemonic::Jmp => branch::encode(mapper, instruction)?,
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
            | Mnemonic::Js => jcc::encode(mapper, instruction)?,
            Mnemonic::Nop => nop::encode(mapper, instruction)?,
            _ => return None,
        };

        out.extend_from_slice(&bytes);
        i += 1;
    }

    Some(out)
}
