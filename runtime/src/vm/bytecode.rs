use std::collections::HashMap;

use iced_x86::{Code, Instruction, OpKind, Register};

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum VMOp {
    PushImm,
    PushReg64,
    SetRegImm,
    SetRegReg,
    SetRegMem,
    SetMemReg,
    CallRel,
    CallReg,
    CallMem,
    Jcc,
}
pub const VM_OP_COUNT: usize = (VMOp::Jcc as u8 + 1) as usize;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VMFlag {
    Carry = 0,      // CF
    Parity = 2,     // PF
    Adjust = 4,     // AF
    Zero = 6,       // ZF
    Sign = 7,       // SF
    Trap = 8,       // TF
    Interrupt = 9,  // IF
    Direction = 10, // DF
    Overflow = 11,  // OF
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VMReg {
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
    Rip,
    Flags,
}
pub const VM_REG_COUNT: usize = (VMReg::Flags as u8) as usize;

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
            Register::RIP => Self::Rip,
            _ => panic!("unsupported register: {reg:?}"),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VMBits {
    Lower8,
    Higher8,
    Lower16,
    Lower32,
    Lower64,
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

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VMSeg {
    None,
    Gs,
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

impl From<&Instruction> for VMMem {
    fn from(instruction: &Instruction) -> Self {
        let base = VMReg::from(instruction.memory_base());
        let index = VMReg::from(instruction.memory_index());
        let scale = instruction.memory_index_scale() as u8;
        let displacement = if instruction.is_ip_rel_memory_operand() {
            (instruction.memory_displacement64() as i64 - instruction.next_ip() as i64) as i32
        } else {
            instruction.memory_displacement64() as i32
        };
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

impl VMMem {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(7);
        bytes.push(self.base as u8);
        bytes.push(self.index as u8);
        bytes.push(self.scale);
        bytes.extend_from_slice(&self.displacement.to_le_bytes());
        bytes.push(self.seg as u8);
        bytes
    }
}

pub enum VMCmd<'a> {
    PushImm {
        len: u8,
        vop: VMOp,
        bits: VMBits,
        src: &'a [u8],
    },
    PushReg64 {
        len: u8,
        vop: VMOp,
        src: VMReg,
    },
    RegImm {
        len: u8,
        vop: VMOp,
        bits: VMBits,
        dst: VMReg,
        src: &'a [u8],
    },
    RegReg {
        len: u8,
        vop: VMOp,
        bits: VMBits,
        dst: VMReg,
        src: VMReg,
    },
    RegMem {
        len: u8,
        vop: VMOp,
        bits: VMBits,
        dst: VMReg,
        src: VMMem,
    },
    MemReg {
        len: u8,
        vop: VMOp,
        bits: VMBits,
        dst: VMMem,
        src: VMReg,
    },
    CallRel {
        len: u8,
        vop: VMOp,
        dst: i32,
    },
    CallReg {
        len: u8,
        vop: VMOp,
        dst: VMReg,
    },
    CallMem {
        len: u8,
        vop: VMOp,
        dst: VMMem,
    },
    Jcc {
        len: u8,
        vop: VMOp,
        flag: VMFlag,
        set: u8,
        dst: i32,
    },
}

impl<'a> VMCmd<'a> {
    fn encode(&self) -> Vec<u8> {
        match self {
            VMCmd::PushImm {
                len,
                vop,
                bits,
                src,
            } => {
                let mut bytes = vec![*len, *vop as u8, *bits as u8];
                bytes.extend_from_slice(src);
                bytes
            }
            VMCmd::PushReg64 { len, vop, src } => {
                let bytes = vec![*len, *vop as u8, *src as u8];
                bytes
            }
            Self::RegImm {
                len,
                vop,
                bits,
                dst,
                src,
            } => {
                let mut bytes = vec![*len, *vop as u8, *bits as u8, *dst as u8];
                bytes.extend_from_slice(src);
                bytes
            }
            Self::RegReg {
                len,
                vop,
                bits,
                dst,
                src,
            } => {
                let bytes = vec![*len, *vop as u8, *bits as u8, *dst as u8, *src as u8];
                bytes
            }
            Self::RegMem {
                len,
                vop,
                bits,
                dst,
                src,
            } => {
                let mut bytes = vec![*len, *vop as u8, *bits as u8, *dst as u8];
                bytes.extend_from_slice(&src.encode());
                bytes
            }
            Self::MemReg {
                len,
                vop,
                bits,
                dst,
                src,
            } => {
                let mut bytes = vec![*len, *vop as u8, *bits as u8];
                bytes.extend_from_slice(&dst.encode());
                bytes.push(*src as u8);
                bytes
            }
            Self::CallRel { len, vop, dst } => {
                let mut bytes = vec![*len, *vop as u8];
                bytes.extend_from_slice(&dst.to_le_bytes());
                bytes
            }
            Self::CallReg { len, vop, dst } => {
                let bytes = vec![*len, *vop as u8, *dst as u8];
                bytes
            }
            Self::CallMem { len, vop, dst } => {
                let mut bytes = vec![*len, *vop as u8];
                bytes.extend_from_slice(&dst.encode());
                bytes
            }
            Self::Jcc {
                len,
                vop,
                flag,
                set,
                dst,
            } => {
                let mut bytes = vec![*len, *vop as u8, *flag as u8, *set];
                bytes.extend_from_slice(&dst.to_le_bytes());
                bytes
            }
        }
    }
}

pub fn convert(instruction: &Instruction) -> Option<Vec<u8>> {
    let bytecode = match instruction.code() {
        Code::Pushq_imm8 => {
            let src = instruction.immediate8();
            VMCmd::PushImm {
                len: instruction.len() as u8,
                vop: VMOp::PushImm,
                bits: VMBits::Lower8,
                src: &src.to_le_bytes(),
            }
        }
        Code::Push_imm16 => {
            let src = instruction.immediate16();
            VMCmd::PushImm {
                len: instruction.len() as u8,
                vop: VMOp::PushImm,
                bits: VMBits::Lower16,
                src: &src.to_le_bytes(),
            }
        }
        Code::Pushq_imm32 => {
            let src = instruction.immediate32();
            VMCmd::PushImm {
                len: instruction.len() as u8,
                vop: VMOp::PushImm,
                bits: VMBits::Lower32,
                src: &src.to_le_bytes(),
            }
        }
        Code::Push_r64 => {
            let reg = instruction.op0_register();
            let src = VMReg::from(reg);
            VMCmd::PushReg64 {
                len: instruction.len() as u8,
                vop: VMOp::PushReg64,
                src: src,
            }
        }
        Code::Mov_r8_imm8 => {
            let reg = instruction.op0_register();
            let bits = VMBits::from(reg);
            let dst = VMReg::from(reg);
            let src = instruction.immediate8();
            VMCmd::RegImm {
                len: instruction.len() as u8,
                vop: VMOp::SetRegImm,
                bits,
                dst,
                src: &src.to_le_bytes(),
            }
        }
        Code::Mov_r16_imm16 => {
            let reg = instruction.op0_register();
            let dst = VMReg::from(reg);
            let src = instruction.immediate16();
            VMCmd::RegImm {
                len: instruction.len() as u8,
                vop: VMOp::SetRegImm,
                bits: VMBits::Lower16,
                dst,
                src: &src.to_le_bytes(),
            }
        }
        Code::Mov_r32_imm32 => {
            let reg = instruction.op0_register();
            let dst = VMReg::from(reg);
            let src = instruction.immediate32();
            VMCmd::RegImm {
                len: instruction.len() as u8,
                vop: VMOp::SetRegImm,
                bits: VMBits::Lower32,
                dst,
                src: &src.to_le_bytes(),
            }
        }
        Code::Mov_r64_imm64 => {
            let reg = instruction.op0_register();
            let dst = VMReg::from(reg);
            let src = instruction.immediate64();
            VMCmd::RegImm {
                len: instruction.len() as u8,
                vop: VMOp::SetRegImm,
                bits: VMBits::Lower64,
                dst,
                src: &src.to_le_bytes(),
            }
        }
        Code::Mov_r64_rm64 | Code::Mov_r32_rm32 | Code::Mov_r16_rm16 | Code::Mov_r8_rm8 => {
            let reg = instruction.op0_register();
            let bits = VMBits::from(reg);
            let dst = VMReg::from(reg);

            match instruction.op1_kind() {
                OpKind::Register => {
                    let src = VMReg::from(instruction.op1_register());
                    VMCmd::RegReg {
                        len: instruction.len() as u8,
                        vop: VMOp::SetRegReg,
                        bits,
                        dst,
                        src,
                    }
                }
                OpKind::Memory => {
                    let src = VMMem::from(instruction);
                    VMCmd::RegMem {
                        len: instruction.len() as u8,
                        vop: VMOp::SetRegMem,
                        bits,
                        dst,
                        src,
                    }
                }
                _ => return None,
            }
        }
        Code::Mov_rm64_r64 | Code::Mov_rm32_r32 | Code::Mov_rm16_r16 | Code::Mov_rm8_r8 => {
            let reg = instruction.op1_register();
            let bits = VMBits::from(reg);
            let src = VMReg::from(reg);

            match instruction.op0_kind() {
                OpKind::Register => {
                    let dst = VMReg::from(instruction.op0_register());
                    VMCmd::RegReg {
                        len: instruction.len() as u8,
                        vop: VMOp::SetRegReg,
                        bits,
                        dst,
                        src,
                    }
                }
                OpKind::Memory => {
                    let dst = VMMem::from(instruction);
                    VMCmd::MemReg {
                        len: instruction.len() as u8,
                        vop: VMOp::SetMemReg,
                        bits,
                        dst,
                        src,
                    }
                }
                _ => return None,
            }
        }
        Code::Call_rel32_64 => {
            let dst =
                (instruction.memory_displacement64() as i64 - instruction.next_ip() as i64) as i32;
            VMCmd::CallRel {
                len: instruction.len() as u8,
                vop: VMOp::CallRel,
                dst,
            }
        }
        Code::Call_rm64 => match instruction.op0_kind() {
            OpKind::Register => {
                let dst = VMReg::from(instruction.op0_register());
                VMCmd::CallReg {
                    len: instruction.len() as u8,
                    vop: VMOp::CallReg,
                    dst,
                }
            }
            OpKind::Memory => {
                let dst = VMMem::from(instruction);
                VMCmd::CallMem {
                    len: instruction.len() as u8,
                    vop: VMOp::CallMem,
                    dst,
                }
            }
            _ => return None,
        },
        Code::Je_rel32_64 => {
            let dst =
                (instruction.memory_displacement64() as i64 - instruction.next_ip() as i64) as i32;
            VMCmd::Jcc {
                len: instruction.len() as u8,
                vop: VMOp::Jcc,
                flag: VMFlag::Zero,
                set: 1,
                dst,
            }
        }
        Code::Jne_rel32_64 => {
            let dst =
                (instruction.memory_displacement64() as i64 - instruction.next_ip() as i64) as i32;
            VMCmd::Jcc {
                len: instruction.len() as u8,
                vop: VMOp::Jcc,
                flag: VMFlag::Zero,
                set: 0,
                dst,
            }
        }
        Code::Jb_rel32_64 => {
            let dst =
                (instruction.memory_displacement64() as i64 - instruction.next_ip() as i64) as i32;
            VMCmd::Jcc {
                len: instruction.len() as u8,
                vop: VMOp::Jcc,
                flag: VMFlag::Carry,
                set: 1,
                dst,
            }
        }
        Code::Js_rel32_64 => {
            let dst =
                (instruction.memory_displacement64() as i64 - instruction.next_ip() as i64) as i32;
            VMCmd::Jcc {
                len: instruction.len() as u8,
                vop: VMOp::Jcc,
                flag: VMFlag::Sign,
                set: 1,
                dst,
            }
        }
        Code::Jns_rel32_64 => {
            let dst =
                (instruction.memory_displacement64() as i64 - instruction.next_ip() as i64) as i32;
            VMCmd::Jcc {
                len: instruction.len() as u8,
                vop: VMOp::Jcc,
                flag: VMFlag::Sign,
                set: 0,
                dst,
            }
        }
        Code::Jp_rel32_64 => {
            let dst =
                (instruction.memory_displacement64() as i64 - instruction.next_ip() as i64) as i32;
            VMCmd::Jcc {
                len: instruction.len() as u8,
                vop: VMOp::Jcc,
                flag: VMFlag::Parity,
                set: 1,
                dst,
            }
        }
        Code::Jnp_rel32_64 => {
            let dst =
                (instruction.memory_displacement64() as i64 - instruction.next_ip() as i64) as i32;
            VMCmd::Jcc {
                len: instruction.len() as u8,
                vop: VMOp::Jcc,
                flag: VMFlag::Parity,
                set: 0,
                dst,
            }
        }
        Code::Jo_rel32_64 => {
            let dst =
                (instruction.memory_displacement64() as i64 - instruction.next_ip() as i64) as i32;
            VMCmd::Jcc {
                len: instruction.len() as u8,
                vop: VMOp::Jcc,
                flag: VMFlag::Overflow,
                set: 1,
                dst,
            }
        }
        Code::Jno_rel32_64 => {
            let dst =
                (instruction.memory_displacement64() as i64 - instruction.next_ip() as i64) as i32;
            VMCmd::Jcc {
                len: instruction.len() as u8,
                vop: VMOp::Jcc,
                flag: VMFlag::Overflow,
                set: 0,
                dst,
            }
        }
        _ => return None,
    };

    Some(bytecode.encode())
}

#[derive(Default)]
pub struct VMBytecode {
    address_to_offset: HashMap<u32, u32>,
    bytecode_to_offset: HashMap<Vec<u8>, u32>,
    bytecode: Vec<u8>,
}

impl VMBytecode {
    pub fn set(&mut self, key: u32, bytecode: Vec<u8>) {
        if let Some(&existing_offset) = self.bytecode_to_offset.get(&bytecode) {
            self.address_to_offset.insert(key, existing_offset);
            return;
        }

        let offset = self.bytecode.len() as u32;
        self.bytecode.extend_from_slice(&bytecode);

        self.bytecode_to_offset.insert(bytecode, offset);
        self.address_to_offset.insert(key, offset);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut entries = self.address_to_offset.iter().collect::<Vec<(&u32, &u32)>>();
        entries.sort_by_key(|&(k, _)| *k);

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&entries.len().to_le_bytes());

        for (&address, &offset) in &entries {
            bytes.extend_from_slice(&address.to_le_bytes());
            bytes.extend_from_slice(&offset.to_le_bytes());
        }

        bytes.extend_from_slice(&self.bytecode);
        bytes
    }
}
