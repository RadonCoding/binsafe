use iced_x86::{Code, Instruction, Mnemonic, OpKind, Register};

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum VMOp {
    Invalid,
    PushImm,
    PushReg64,
    PopReg64,
    SetRegImm,
    SetRegReg,
    SetRegMem,
    SetMemReg,
    SetMemImm,
    AddSubRegImm,
    AddSubRegReg,
    AddSubMemImm,
    BranchRel,
    BranchReg,
    BranchMem,
    Jcc,
    Nop,
}
pub const VM_OP_COUNT: usize = VMOp::Nop as u8 as usize;

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

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VMTest {
    CMP,
    EQ,
    NEQ,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VMLogic {
    AND,
    OR,
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

impl VMMem {
    fn new(address: u64, instruction: &Instruction) -> Self {
        let base = VMReg::from(instruction.memory_base());
        let index = VMReg::from(instruction.memory_index());
        let scale = instruction.memory_index_scale() as u8;
        let displacement = if instruction.is_ip_rel_memory_operand() {
            (instruction.memory_displacement64() as i64 - address as i64) as i32
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

#[derive(Debug, Clone)]
pub struct VMCond {
    pub cmp: VMTest,
    pub lhs: u8,
    pub rhs: u8,
}

impl VMCond {
    pub fn encode(&self) -> Vec<u8> {
        vec![self.cmp as u8, self.lhs, self.rhs]
    }
}

pub enum VMCmd<'a> {
    PushImm {
        vop: VMOp,
        bits: VMBits,
        src: &'a [u8],
    },
    PushReg64 {
        vop: VMOp,
        src: VMReg,
    },
    PopReg64 {
        vop: VMOp,
        dst: VMReg,
    },
    RegImm {
        vop: VMOp,
        bits: VMBits,
        dst: VMReg,
        src: &'a [u8],
    },
    RegReg {
        vop: VMOp,
        dbits: VMBits,
        dst: VMReg,
        sbits: VMBits,
        src: VMReg,
    },
    RegMem {
        vop: VMOp,
        bits: VMBits,
        load: bool,
        dst: VMReg,
        src: VMMem,
    },
    MemImm {
        vop: VMOp,
        dst: VMMem,
        src: &'a [u8],
    },
    MemReg {
        vop: VMOp,
        bits: VMBits,
        dst: VMMem,
        src: VMReg,
    },
    AddSubRegImm {
        vop: VMOp,
        bits: VMBits,
        dst: VMReg,
        sub: bool,
        store: bool,
        src: &'a [u8],
    },
    AddSubRegReg {
        vop: VMOp,
        dbits: VMBits,
        dst: VMReg,
        sbits: VMBits,
        src: VMReg,
        sub: bool,
        store: bool,
    },
    AddSubMemImm {
        vop: VMOp,
        dst: VMMem,
        sub: bool,
        store: bool,
        src: &'a [u8],
    },
    BranchRel {
        vop: VMOp,
        dst: i32,
        ret: bool,
    },
    BranchReg {
        vop: VMOp,
        dst: VMReg,
        ret: bool,
    },
    BranchMem {
        vop: VMOp,
        dst: VMMem,
        ret: bool,
    },
    Jcc {
        vop: VMOp,
        logic: VMLogic,
        conds: Vec<VMCond>,
        dst: i32,
    },
    Nop {
        vop: VMOp,
    },
}

impl<'a> VMCmd<'a> {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            VMCmd::PushImm { vop, bits, src } => {
                let mut bytes = vec![*vop as u8, *bits as u8];
                bytes.extend_from_slice(src);
                bytes
            }
            Self::PushReg64 { vop, src } => {
                let bytes = vec![*vop as u8, *src as u8];
                bytes
            }
            Self::PopReg64 { vop, dst } => {
                let bytes = vec![*vop as u8, *dst as u8];
                bytes
            }
            Self::RegImm {
                vop,
                bits,
                dst,
                src,
            } => {
                let mut bytes = vec![*vop as u8, *bits as u8, *dst as u8];
                bytes.extend_from_slice(src);
                bytes
            }
            Self::RegReg {
                vop,
                dbits,
                dst,
                sbits,
                src,
            } => {
                let bytes = vec![
                    *vop as u8,
                    *dbits as u8,
                    *dst as u8,
                    *sbits as u8,
                    *src as u8,
                ];
                bytes
            }
            Self::RegMem {
                vop,
                bits,
                load,
                dst,
                src,
            } => {
                let mut bytes = vec![*vop as u8, *bits as u8, *load as u8, *dst as u8];
                bytes.extend_from_slice(&src.encode());
                bytes
            }
            Self::MemImm { vop, dst, src } => {
                let mut bytes = vec![*vop as u8];
                bytes.extend_from_slice(&dst.encode());
                bytes.push(src.len() as u8);
                bytes.extend_from_slice(src);
                bytes
            }
            Self::MemReg {
                vop,
                bits,
                dst,
                src,
            } => {
                let mut bytes = vec![*vop as u8, *bits as u8];
                bytes.extend_from_slice(&dst.encode());
                bytes.push(*src as u8);
                bytes
            }
            Self::AddSubRegImm {
                vop,
                bits,
                dst,
                src,
                sub,
                store,
            } => {
                let mut bytes = vec![
                    *vop as u8,
                    *bits as u8,
                    *dst as u8,
                    *sub as u8,
                    *store as u8,
                ];
                bytes.extend_from_slice(src);
                bytes
            }
            Self::AddSubRegReg {
                vop,
                dbits,
                dst,
                sbits,
                src,
                sub,
                store,
            } => {
                let bytes = vec![
                    *vop as u8,
                    *dbits as u8,
                    *dst as u8,
                    *sbits as u8,
                    *src as u8,
                    *sub as u8,
                    *store as u8,
                ];
                bytes
            }
            Self::AddSubMemImm {
                vop,
                dst,
                src,
                sub,
                store,
            } => {
                let mut bytes = vec![*vop as u8];
                bytes.extend_from_slice(&dst.encode());
                bytes.push(*sub as u8);
                bytes.push(*store as u8);
                bytes.push(src.len() as u8);
                bytes.extend_from_slice(src);
                bytes
            }
            Self::BranchRel { vop, dst, ret } => {
                let mut bytes = vec![*vop as u8, *ret as u8];
                bytes.extend_from_slice(&dst.to_le_bytes());
                bytes
            }
            Self::BranchReg { vop, dst, ret } => {
                vec![*vop as u8, *ret as u8, *dst as u8]
            }
            Self::BranchMem { vop, dst, ret } => {
                let mut bytes = vec![*vop as u8, *ret as u8];
                bytes.extend_from_slice(&dst.encode());
                bytes
            }
            Self::Jcc {
                vop,
                logic,
                conds,
                dst,
            } => {
                let mut bytes = vec![*vop as u8, *logic as u8, conds.len() as u8];

                for op in conds {
                    bytes.extend_from_slice(&op.encode());
                }
                bytes.extend_from_slice(&dst.to_le_bytes());
                bytes
            }
            Self::Nop { vop } => {
                let bytes = vec![*vop as u8];
                bytes
            }
        }
    }
}

pub fn convert(address: u64, instruction: &Instruction) -> Option<Vec<u8>> {
    let bytecode = match instruction.code() {
        Code::Pushq_imm8 => {
            let src = instruction.immediate8();
            VMCmd::PushImm {
                vop: VMOp::PushImm,
                bits: VMBits::Lower8,
                src: &src.to_le_bytes(),
            }
        }
        Code::Push_imm16 => {
            let src = instruction.immediate16();
            VMCmd::PushImm {
                vop: VMOp::PushImm,
                bits: VMBits::Lower16,
                src: &src.to_le_bytes(),
            }
        }
        Code::Pushq_imm32 => {
            let src = instruction.immediate32();
            VMCmd::PushImm {
                vop: VMOp::PushImm,
                bits: VMBits::Lower32,
                src: &src.to_le_bytes(),
            }
        }
        Code::Push_r64 => {
            let reg = instruction.op0_register();
            let src = VMReg::from(reg);
            VMCmd::PushReg64 {
                vop: VMOp::PushReg64,
                src: src,
            }
        }
        Code::Pop_r64 => {
            let reg = instruction.op0_register();
            let dst = VMReg::from(reg);
            VMCmd::PopReg64 {
                vop: VMOp::PopReg64,
                dst,
            }
        }
        Code::Mov_r8_imm8 => {
            let reg = instruction.op0_register();
            let bits = VMBits::from(reg);
            let dst = VMReg::from(reg);
            let src = instruction.immediate8();
            VMCmd::RegImm {
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
                vop: VMOp::SetRegImm,
                bits: VMBits::Lower64,
                dst,
                src: &src.to_le_bytes(),
            }
        }
        Code::Mov_r64_rm64 | Code::Mov_r32_rm32 | Code::Mov_r16_rm16 | Code::Mov_r8_rm8 => {
            let dreg = instruction.op0_register();
            let dbits = VMBits::from(dreg);
            let dst = VMReg::from(dreg);

            match instruction.op1_kind() {
                OpKind::Register => {
                    let sreg = instruction.op1_register();
                    let sbits = VMBits::from(sreg);
                    let src = VMReg::from(sreg);
                    VMCmd::RegReg {
                        vop: VMOp::SetRegReg,
                        dbits,
                        dst,
                        sbits,
                        src,
                    }
                }
                OpKind::Memory => {
                    let src = VMMem::new(address, instruction);
                    VMCmd::RegMem {
                        vop: VMOp::SetRegMem,
                        bits: dbits,
                        load: true,
                        dst,
                        src,
                    }
                }
                _ => return None,
            }
        }
        Code::Mov_rm64_r64 | Code::Mov_rm32_r32 | Code::Mov_rm16_r16 | Code::Mov_rm8_r8 => {
            let sreg = instruction.op1_register();
            let sbits = VMBits::from(sreg);
            let src = VMReg::from(sreg);

            match instruction.op0_kind() {
                OpKind::Register => {
                    let dreg = instruction.op0_register();
                    let dbits = VMBits::from(dreg);
                    let dst = VMReg::from(dreg);
                    VMCmd::RegReg {
                        vop: VMOp::SetRegReg,
                        dbits,
                        dst,
                        sbits,
                        src,
                    }
                }
                OpKind::Memory => {
                    let dst = VMMem::new(address, instruction);
                    VMCmd::MemReg {
                        vop: VMOp::SetMemReg,
                        bits: sbits,
                        dst,
                        src,
                    }
                }
                _ => return None,
            }
        }
        Code::Mov_rm64_imm32 | Code::Mov_rm32_imm32 | Code::Mov_rm16_imm16 | Code::Mov_rm8_imm8 => {
            let (src, size) = match instruction.code() {
                Code::Mov_rm8_imm8 => (instruction.immediate8() as u64, 1),
                Code::Mov_rm16_imm16 => (instruction.immediate16() as u64, 2),
                Code::Mov_rm32_imm32 => (instruction.immediate32() as u64, 4),
                Code::Mov_rm64_imm32 => (instruction.immediate32to64() as u64, 8),
                _ => unreachable!(),
            };

            match instruction.op0_kind() {
                OpKind::Register => {
                    let reg = instruction.op0_register();
                    let bits = VMBits::from(reg);
                    let dst = VMReg::from(reg);
                    VMCmd::RegImm {
                        vop: VMOp::SetRegImm,
                        bits,
                        dst,
                        src: &src.to_le_bytes()[..size],
                    }
                }
                OpKind::Memory => {
                    let dst = VMMem::new(address, instruction);
                    VMCmd::MemImm {
                        vop: VMOp::SetMemImm,
                        dst,
                        src: &src.to_le_bytes()[..size],
                    }
                }
                _ => return None,
            }
        }
        Code::Add_rm8_imm8
        | Code::Add_rm16_imm8
        | Code::Add_rm32_imm8
        | Code::Add_rm64_imm8
        | Code::Sub_rm8_imm8
        | Code::Sub_rm16_imm8
        | Code::Sub_rm32_imm8
        | Code::Sub_rm64_imm8
        | Code::Cmp_rm8_imm8
        | Code::Cmp_rm16_imm8
        | Code::Cmp_rm32_imm8
        | Code::Cmp_rm64_imm8 => {
            let sub = matches!(instruction.mnemonic(), Mnemonic::Sub | Mnemonic::Cmp);
            let store = matches!(instruction.mnemonic(), Mnemonic::Add | Mnemonic::Sub);

            let (src, size) = match instruction.op1_kind() {
                OpKind::Immediate8 => (instruction.immediate8() as u64, 1),
                OpKind::Immediate8to16 => (instruction.immediate8to16() as u64, 2),
                OpKind::Immediate8to32 => (instruction.immediate8to32() as u64, 4),
                OpKind::Immediate8to64 => (instruction.immediate8to64() as u64, 8),
                _ => unreachable!(),
            };

            match instruction.op0_kind() {
                OpKind::Register => {
                    let reg = instruction.op0_register();
                    let dst = VMReg::from(reg);
                    let bits = VMBits::from(reg);
                    VMCmd::AddSubRegImm {
                        vop: VMOp::AddSubRegImm,
                        bits,
                        dst,
                        sub,
                        store,
                        src: &src.to_le_bytes()[..size],
                    }
                }
                OpKind::Memory => {
                    let dst = VMMem::new(address, instruction);
                    VMCmd::AddSubMemImm {
                        vop: VMOp::AddSubMemImm,
                        dst,
                        sub,
                        store,
                        src: &src.to_le_bytes()[..size],
                    }
                }
                _ => return None,
            }
        }
        Code::Add_rm16_imm16 | Code::Sub_rm16_imm16 | Code::Cmp_rm16_imm16 => {
            let src = instruction.immediate16();
            let sub = matches!(instruction.mnemonic(), Mnemonic::Sub | Mnemonic::Cmp);
            let store = matches!(instruction.mnemonic(), Mnemonic::Add | Mnemonic::Sub);

            match instruction.op0_kind() {
                OpKind::Register => {
                    let reg = instruction.op0_register();
                    let dst = VMReg::from(reg);
                    let bits = VMBits::from(reg);
                    VMCmd::AddSubRegImm {
                        vop: VMOp::AddSubRegImm,
                        bits,
                        dst,
                        sub,
                        store,
                        src: &src.to_le_bytes(),
                    }
                }
                OpKind::Memory => {
                    let dst = VMMem::new(address, instruction);
                    VMCmd::AddSubMemImm {
                        vop: VMOp::AddSubMemImm,
                        dst,
                        sub,
                        store,
                        src: &src.to_le_bytes(),
                    }
                }
                _ => return None,
            }
        }
        Code::Add_rm32_imm32 | Code::Sub_rm32_imm32 | Code::Cmp_rm32_imm32 => {
            let src = instruction.immediate32();
            let sub = matches!(instruction.mnemonic(), Mnemonic::Sub | Mnemonic::Cmp);
            let store = matches!(instruction.mnemonic(), Mnemonic::Add | Mnemonic::Sub);

            match instruction.op0_kind() {
                OpKind::Register => {
                    let reg = instruction.op0_register();
                    let dst = VMReg::from(reg);
                    let bits = VMBits::from(reg);
                    VMCmd::AddSubRegImm {
                        vop: VMOp::AddSubRegImm,
                        bits,
                        dst,
                        sub,
                        store,
                        src: &src.to_le_bytes(),
                    }
                }
                OpKind::Memory => {
                    let dst = VMMem::new(address, instruction);
                    VMCmd::AddSubMemImm {
                        vop: VMOp::AddSubMemImm,
                        dst,
                        sub,
                        store,
                        src: &src.to_le_bytes(),
                    }
                }
                _ => return None,
            }
        }
        Code::Add_r64_rm64
        | Code::Add_r32_rm32
        | Code::Add_r16_rm16
        | Code::Add_r8_rm8
        | Code::Sub_r64_rm64
        | Code::Sub_r32_rm32
        | Code::Sub_r16_rm16
        | Code::Sub_r8_rm8
        | Code::Cmp_r64_rm64
        | Code::Cmp_r32_rm32
        | Code::Cmp_r16_rm16
        | Code::Cmp_r8_rm8 => {
            let dreg = instruction.op0_register();
            let dbits = VMBits::from(dreg);
            let dst = VMReg::from(dreg);
            let sub = matches!(instruction.mnemonic(), Mnemonic::Sub | Mnemonic::Cmp);
            let store = matches!(instruction.mnemonic(), Mnemonic::Add | Mnemonic::Sub);

            match instruction.op1_kind() {
                OpKind::Register => {
                    let sreg = instruction.op1_register();
                    let sbits = VMBits::from(sreg);
                    let src = VMReg::from(instruction.op1_register());
                    VMCmd::AddSubRegReg {
                        vop: VMOp::AddSubRegReg,
                        dbits,
                        dst,
                        sbits,
                        src,
                        sub,
                        store,
                    }
                }
                // TODO: Implement AddSubRegMem & CmpRegMem
                _ => return None,
            }
        }
        Code::Add_rm64_r64
        | Code::Add_rm32_r32
        | Code::Add_rm16_r16
        | Code::Add_rm8_r8
        | Code::Sub_rm64_r64
        | Code::Sub_rm32_r32
        | Code::Sub_rm16_r16
        | Code::Sub_rm8_r8
        | Code::Cmp_rm64_r64
        | Code::Cmp_rm32_r32
        | Code::Cmp_rm16_r16
        | Code::Cmp_rm8_r8 => {
            let sreg = instruction.op1_register();
            let sbits = VMBits::from(sreg);
            let src = VMReg::from(sreg);
            let sub = matches!(instruction.mnemonic(), Mnemonic::Sub | Mnemonic::Cmp);
            let store = matches!(instruction.mnemonic(), Mnemonic::Add | Mnemonic::Sub);

            match instruction.op0_kind() {
                OpKind::Register => {
                    let dreg = instruction.op0_register();
                    let dbits = VMBits::from(dreg);
                    let dst = VMReg::from(dreg);
                    VMCmd::AddSubRegReg {
                        vop: VMOp::AddSubRegReg,
                        dbits,
                        dst,
                        sbits,
                        src,
                        sub,
                        store,
                    }
                }
                // TODO: Implement AddSubMemReg & CmpMemReg
                _ => return None,
            }
        }
        Code::Lea_r16_m | Code::Lea_r32_m | Code::Lea_r64_m => {
            let reg = instruction.op0_register();
            let bits = VMBits::from(reg);
            let dst = VMReg::from(reg);
            let src = VMMem::new(address, instruction);

            VMCmd::RegMem {
                vop: VMOp::SetRegMem,
                bits,
                load: false,
                dst,
                src,
            }
        }
        Code::Call_rel32_64 => {
            let dst = (instruction.memory_displacement64() as i64 - address as i64) as i32;
            VMCmd::BranchRel {
                vop: VMOp::BranchRel,
                dst,
                ret: true,
            }
        }
        Code::Call_rm64 => match instruction.op0_kind() {
            OpKind::Register => VMCmd::BranchReg {
                vop: VMOp::BranchReg,
                dst: VMReg::from(instruction.op0_register()),
                ret: true,
            },
            OpKind::Memory => VMCmd::BranchMem {
                vop: VMOp::BranchMem,
                dst: VMMem::new(address, instruction),
                ret: true,
            },
            _ => return None,
        },
        Code::Jmp_rel8_64 | Code::Jmp_rel32_64 => {
            let dst = (instruction.memory_displacement64() as i64 - address as i64) as i32;
            VMCmd::BranchRel {
                vop: VMOp::BranchRel,
                dst,
                ret: false,
            }
        }
        Code::Jmp_rm64 => match instruction.op0_kind() {
            OpKind::Register => VMCmd::BranchReg {
                vop: VMOp::BranchReg,
                dst: VMReg::from(instruction.op0_register()),
                ret: false,
            },
            OpKind::Memory => VMCmd::BranchMem {
                vop: VMOp::BranchMem,
                dst: VMMem::new(address, instruction),
                ret: false,
            },
            _ => return None,
        },
        Code::Ja_rel32_64 | Code::Ja_rel8_64 => {
            let dst = (instruction.memory_displacement64() as i64 - address as i64) as i32;
            // JA = CF=0 AND ZF=0
            VMCmd::Jcc {
                vop: VMOp::Jcc,
                logic: VMLogic::AND,
                conds: vec![
                    VMCond {
                        cmp: VMTest::CMP,
                        lhs: VMFlag::Carry as u8,
                        rhs: 0,
                    },
                    VMCond {
                        cmp: VMTest::CMP,
                        lhs: VMFlag::Zero as u8,
                        rhs: 0,
                    },
                ],
                dst,
            }
        }
        Code::Jae_rel32_64 | Code::Jae_rel8_64 => {
            let dst = (instruction.memory_displacement64() as i64 - address as i64) as i32;
            // JAE = CF=0
            VMCmd::Jcc {
                vop: VMOp::Jcc,
                logic: VMLogic::AND,
                conds: vec![VMCond {
                    cmp: VMTest::CMP,
                    lhs: VMFlag::Carry as u8,
                    rhs: 0,
                }],
                dst,
            }
        }
        Code::Jb_rel32_64 | Code::Jb_rel8_64 => {
            let dst = (instruction.memory_displacement64() as i64 - address as i64) as i32;
            // JB = CF=1
            VMCmd::Jcc {
                vop: VMOp::Jcc,
                logic: VMLogic::AND,
                conds: vec![VMCond {
                    cmp: VMTest::CMP,
                    lhs: VMFlag::Carry as u8,
                    rhs: 1,
                }],
                dst,
            }
        }
        Code::Jbe_rel32_64 | Code::Jbe_rel8_64 => {
            let dst = (instruction.memory_displacement64() as i64 - address as i64) as i32;
            // JBE = CF=1 OR ZF=1
            VMCmd::Jcc {
                vop: VMOp::Jcc,
                logic: VMLogic::OR,
                conds: vec![
                    VMCond {
                        cmp: VMTest::CMP,
                        lhs: VMFlag::Carry as u8,
                        rhs: 1,
                    },
                    VMCond {
                        cmp: VMTest::CMP,
                        lhs: VMFlag::Zero as u8,
                        rhs: 1,
                    },
                ],
                dst,
            }
        }
        Code::Je_rel32_64 | Code::Je_rel8_64 => {
            let dst = (instruction.memory_displacement64() as i64 - address as i64) as i32;
            // JE = ZF=1
            VMCmd::Jcc {
                vop: VMOp::Jcc,
                logic: VMLogic::AND,
                conds: vec![VMCond {
                    cmp: VMTest::CMP,
                    lhs: VMFlag::Zero as u8,
                    rhs: 1,
                }],
                dst,
            }
        }
        Code::Jg_rel32_64 | Code::Jg_rel8_64 => {
            let dst = (instruction.memory_displacement64() as i64 - address as i64) as i32;
            // JG = ZF=0 AND SF=OF
            VMCmd::Jcc {
                vop: VMOp::Jcc,
                logic: VMLogic::AND,
                conds: vec![
                    VMCond {
                        cmp: VMTest::CMP,
                        lhs: VMFlag::Zero as u8,
                        rhs: 0,
                    },
                    VMCond {
                        cmp: VMTest::EQ,
                        lhs: VMFlag::Sign as u8,
                        rhs: VMFlag::Overflow as u8,
                    },
                ],
                dst,
            }
        }
        Code::Jge_rel32_64 | Code::Jge_rel8_64 => {
            let dst = (instruction.memory_displacement64() as i64 - address as i64) as i32;
            // JGE = SF=OF
            VMCmd::Jcc {
                vop: VMOp::Jcc,
                logic: VMLogic::AND,
                conds: vec![VMCond {
                    cmp: VMTest::EQ,
                    lhs: VMFlag::Sign as u8,
                    rhs: VMFlag::Overflow as u8,
                }],
                dst,
            }
        }
        Code::Jl_rel32_64 | Code::Jl_rel8_64 => {
            let dst = (instruction.memory_displacement64() as i64 - address as i64) as i32;
            // JL = SF<>OF
            VMCmd::Jcc {
                vop: VMOp::Jcc,
                logic: VMLogic::AND,
                conds: vec![VMCond {
                    cmp: VMTest::NEQ,
                    lhs: VMFlag::Sign as u8,
                    rhs: VMFlag::Overflow as u8,
                }],
                dst,
            }
        }
        Code::Jle_rel32_64 | Code::Jle_rel8_64 => {
            let dst = (instruction.memory_displacement64() as i64 - address as i64) as i32;
            // JLE = ZF=1 OR SF<>OF
            VMCmd::Jcc {
                vop: VMOp::Jcc,
                logic: VMLogic::OR,
                conds: vec![
                    VMCond {
                        cmp: VMTest::CMP,
                        lhs: VMFlag::Zero as u8,
                        rhs: 1,
                    },
                    VMCond {
                        cmp: VMTest::NEQ,
                        lhs: VMFlag::Sign as u8,
                        rhs: VMFlag::Overflow as u8,
                    },
                ],
                dst,
            }
        }
        Code::Jne_rel32_64 | Code::Jne_rel8_64 => {
            let dst = (instruction.memory_displacement64() as i64 - address as i64) as i32;
            // JNE = ZF=0
            VMCmd::Jcc {
                vop: VMOp::Jcc,
                logic: VMLogic::AND,
                conds: vec![VMCond {
                    cmp: VMTest::CMP,
                    lhs: VMFlag::Zero as u8,
                    rhs: 0,
                }],
                dst,
            }
        }
        Code::Jno_rel32_64 | Code::Jno_rel8_64 => {
            let dst = (instruction.memory_displacement64() as i64 - address as i64) as i32;
            // JNO = OF=0
            VMCmd::Jcc {
                vop: VMOp::Jcc,
                logic: VMLogic::AND,
                conds: vec![VMCond {
                    cmp: VMTest::CMP,
                    lhs: VMFlag::Overflow as u8,
                    rhs: 0,
                }],
                dst,
            }
        }
        Code::Jnp_rel32_64 | Code::Jnp_rel8_64 => {
            let dst = (instruction.memory_displacement64() as i64 - address as i64) as i32;
            // JNP = PF=0
            VMCmd::Jcc {
                vop: VMOp::Jcc,
                logic: VMLogic::AND,
                conds: vec![VMCond {
                    cmp: VMTest::CMP,
                    lhs: VMFlag::Parity as u8,
                    rhs: 0,
                }],
                dst,
            }
        }
        Code::Jns_rel32_64 | Code::Jns_rel8_64 => {
            let dst = (instruction.memory_displacement64() as i64 - address as i64) as i32;
            // JNS = SF=0
            VMCmd::Jcc {
                vop: VMOp::Jcc,
                logic: VMLogic::AND,
                conds: vec![VMCond {
                    cmp: VMTest::CMP,
                    lhs: VMFlag::Sign as u8,
                    rhs: 0,
                }],
                dst,
            }
        }
        Code::Jo_rel32_64 | Code::Jo_rel8_64 => {
            let dst = (instruction.memory_displacement64() as i64 - address as i64) as i32;
            // JO = OF=1
            VMCmd::Jcc {
                vop: VMOp::Jcc,
                logic: VMLogic::AND,
                conds: vec![VMCond {
                    cmp: VMTest::CMP,
                    lhs: VMFlag::Overflow as u8,
                    rhs: 1,
                }],
                dst,
            }
        }
        Code::Jp_rel32_64 | Code::Jp_rel8_64 => {
            let dst = (instruction.memory_displacement64() as i64 - address as i64) as i32;
            // JP = PF=1
            VMCmd::Jcc {
                vop: VMOp::Jcc,
                logic: VMLogic::AND,
                conds: vec![VMCond {
                    cmp: VMTest::CMP,
                    lhs: VMFlag::Parity as u8,
                    rhs: 1,
                }],
                dst,
            }
        }
        Code::Js_rel32_64 | Code::Js_rel8_64 => {
            let dst = (instruction.memory_displacement64() as i64 - address as i64) as i32;
            // JS = SF=1
            VMCmd::Jcc {
                vop: VMOp::Jcc,
                logic: VMLogic::AND,
                conds: vec![VMCond {
                    cmp: VMTest::CMP,
                    lhs: VMFlag::Sign as u8,
                    rhs: 1,
                }],
                dst,
            }
        }
        Code::Nopw | Code::Nopd | Code::Nopq | Code::Nop_rm16 | Code::Nop_rm32 | Code::Nop_rm64 => {
            VMCmd::Nop { vop: VMOp::Nop }
        }
        _ => {
            // println!("{instruction} -> {:?}", instruction.code());
            return None;
        }
    };

    Some(bytecode.encode())
}
