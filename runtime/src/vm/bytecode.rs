use iced_x86::{Code, Instruction, Mnemonic, OpKind, Register};

use crate::mapper::{mapped, Mapper};

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
    pub displ: i32,
    pub seg: VMSeg,
}

impl VMMem {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(mapper.index(self.base));
        bytes.push(mapper.index(self.index));
        bytes.push(self.scale);
        bytes.extend_from_slice(&self.displ.to_le_bytes());
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
            displ: displacement,
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

impl VMCond {
    pub fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(self.cmp), self.lhs, self.rhs]
    }
}

pub enum VMCmd<'a> {
    PushPopRegs {
        vop: VMOp,
        pop: bool,
        seq: Vec<u8>,
    },
    PushImm {
        vop: VMOp,
        src: &'a [u8],
    },
    PushReg {
        vop: VMOp,
        src: VMReg,
    },
    PopReg {
        vop: VMOp,
        dst: VMReg,
    },
    SetRegImm {
        vop: VMOp,
        dbits: VMBits,
        dst: VMReg,
        src: &'a [u8],
    },
    SetRegReg {
        vop: VMOp,
        dbits: VMBits,
        dst: VMReg,
        sbits: VMBits,
        src: VMReg,
    },
    SetRegMem {
        vop: VMOp,
        dbits: VMBits,
        load: bool,
        dst: VMReg,
        src: VMMem,
    },
    SetMemImm {
        vop: VMOp,
        dst: VMMem,
        src: &'a [u8],
    },
    SetMemReg {
        vop: VMOp,
        sbits: VMBits,
        dst: VMMem,
        src: VMReg,
    },
    AddSubRegImm {
        vop: VMOp,
        dbits: VMBits,
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
    AddSubRegMem {
        vop: VMOp,
        src: VMMem,
        sub: bool,
        store: bool,
        dbits: VMBits,
        dst: VMReg,
    },
    AddSubMemImm {
        vop: VMOp,
        dst: VMMem,
        sub: bool,
        store: bool,
        src: &'a [u8],
    },
    AddSubMemReg {
        vop: VMOp,
        dst: VMMem,
        sub: bool,
        store: bool,
        sbits: VMBits,
        src: VMReg,
    },
    BranchImm {
        vop: VMOp,
        ret: bool,
        dst: u32,
    },
    BranchReg {
        vop: VMOp,
        ret: bool,
        dst: VMReg,
    },
    BranchMem {
        vop: VMOp,
        ret: bool,
        dst: VMMem,
    },
    Jcc {
        vop: VMOp,
        logic: VMLogic,
        conds: Vec<VMCond>,
        dst: u32,
    },
    Nop {
        vop: VMOp,
    },
}

impl<'a> VMCmd<'a> {
    pub fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        match self {
            Self::PushPopRegs { vop, pop, seq } => {
                let mut bytes = vec![mapper.index(*vop)];
                bytes.push(*pop as u8);
                bytes.push(seq.len() as u8);
                bytes.extend_from_slice(seq);
                bytes
            }
            Self::PushImm { vop, src } => {
                let mut bytes = vec![mapper.index(*vop)];
                bytes.push(src.len() as u8);
                bytes.extend_from_slice(src);
                bytes
            }
            Self::PushReg { vop, src } => {
                let bytes = vec![mapper.index(*vop), mapper.index(*src)];
                bytes
            }
            Self::PopReg { vop, dst } => {
                let bytes = vec![mapper.index(*vop), mapper.index(*dst)];
                bytes
            }
            Self::SetRegImm {
                vop,
                dbits,
                dst,
                src,
            } => {
                let mut bytes = vec![mapper.index(*vop), mapper.index(*dbits), mapper.index(*dst)];
                bytes.extend_from_slice(src);
                bytes
            }
            Self::SetRegReg {
                vop,
                dbits,
                dst,
                sbits,
                src,
            } => {
                let bytes = vec![
                    mapper.index(*vop),
                    mapper.index(*dbits),
                    mapper.index(*dst),
                    mapper.index(*sbits),
                    mapper.index(*src),
                ];
                bytes
            }
            Self::SetRegMem {
                vop,
                dbits,
                load,
                dst,
                src,
            } => {
                let mut bytes = vec![
                    mapper.index(*vop),
                    mapper.index(*dbits),
                    *load as u8,
                    mapper.index(*dst),
                ];
                bytes.extend_from_slice(&src.encode(mapper));
                bytes
            }
            Self::SetMemImm { vop, dst, src } => {
                let mut bytes = vec![mapper.index(*vop)];
                bytes.extend_from_slice(&dst.encode(mapper));
                bytes.push(src.len() as u8);
                bytes.extend_from_slice(src);
                bytes
            }
            Self::SetMemReg {
                vop,
                sbits,
                dst,
                src,
            } => {
                let mut bytes = vec![mapper.index(*vop), mapper.index(*sbits)];
                bytes.extend_from_slice(&dst.encode(mapper));
                bytes.push(mapper.index(*src));
                bytes
            }
            Self::AddSubRegImm {
                vop,
                dbits,
                dst,
                sub,
                store,
                src,
            } => {
                let mut bytes = vec![
                    mapper.index(*vop),
                    mapper.index(*dbits),
                    mapper.index(*dst),
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
                    mapper.index(*vop),
                    mapper.index(*dbits),
                    mapper.index(*dst),
                    mapper.index(*sbits),
                    mapper.index(*src),
                    *sub as u8,
                    *store as u8,
                ];
                bytes
            }
            Self::AddSubRegMem {
                vop,
                src,
                sub,
                store,
                dbits,
                dst,
            } => {
                let mut bytes = vec![mapper.index(*vop)];
                bytes.extend_from_slice(&src.encode(mapper));
                bytes.push(*sub as u8);
                bytes.push(*store as u8);
                bytes.push(mapper.index(*dbits));
                bytes.push(mapper.index(*dst));
                bytes
            }
            Self::AddSubMemImm {
                vop,
                dst,
                sub,
                store,
                src,
            } => {
                let mut bytes = vec![mapper.index(*vop)];
                bytes.extend_from_slice(&dst.encode(mapper));
                bytes.push(*sub as u8);
                bytes.push(*store as u8);
                bytes.push(src.len() as u8);
                bytes.extend_from_slice(src);
                bytes
            }
            Self::AddSubMemReg {
                vop,
                dst,
                sub,
                store,
                sbits,
                src,
            } => {
                let mut bytes = vec![mapper.index(*vop)];
                bytes.extend_from_slice(&dst.encode(mapper));
                bytes.push(*sub as u8);
                bytes.push(*store as u8);
                bytes.push(mapper.index(*sbits));
                bytes.push(mapper.index(*src));
                bytes
            }
            Self::BranchImm { vop, ret, dst } => {
                let mut bytes = vec![mapper.index(*vop), *ret as u8];
                bytes.extend_from_slice(&dst.to_le_bytes());
                bytes
            }
            Self::BranchReg { vop, ret, dst } => {
                vec![mapper.index(*vop), *ret as u8, mapper.index(*dst)]
            }
            Self::BranchMem { vop, ret, dst } => {
                let mut bytes = vec![mapper.index(*vop), *ret as u8];
                bytes.extend_from_slice(&dst.encode(mapper));
                bytes
            }
            Self::Jcc {
                vop,
                logic,
                conds,
                dst,
            } => {
                let mut bytes = vec![mapper.index(*vop), mapper.index(*logic), conds.len() as u8];

                for op in conds {
                    bytes.extend_from_slice(&op.encode(mapper));
                }
                bytes.extend_from_slice(&dst.to_le_bytes());
                bytes
            }
            Self::Nop { vop } => {
                let bytes = vec![mapper.index(*vop)];
                bytes
            }
        }
    }
}

pub fn convert(mapper: &mut Mapper, instructions: &[Instruction]) -> Option<Vec<u8>> {
    let mut vinstructions = Vec::new();

    let mut i = 0;

    while i < instructions.len() {
        let instruction = &instructions[i];
        let code = instruction.code();

        if code == Code::Push_r64 || code == Code::Pop_r64 {
            let mut seq = Vec::new();

            let mut j = i;

            while j < instructions.len() && instructions[j].code() == code {
                let vreg = VMReg::from(instructions[j].op0_register());
                let idx = mapper.index(vreg);
                seq.push(idx);
                j += 1;
            }

            if seq.len() >= 2 {
                let pop = instruction.mnemonic() == Mnemonic::Pop;

                vinstructions.extend_from_slice(
                    &VMCmd::PushPopRegs {
                        vop: VMOp::PushPopRegs,
                        pop,
                        seq,
                    }
                    .encode(mapper),
                );

                i = j;
                continue;
            }
        }

        let bytecode = match code {
            Code::Pushq_imm8 => {
                let src = instruction.immediate8();
                VMCmd::PushImm {
                    vop: VMOp::PushImm,
                    src: &src.to_le_bytes(),
                }
            }
            Code::Push_imm16 => {
                let src = instruction.immediate16();
                VMCmd::PushImm {
                    vop: VMOp::PushImm,
                    src: &src.to_le_bytes(),
                }
            }
            Code::Pushq_imm32 => {
                let src = instruction.immediate32();
                VMCmd::PushImm {
                    vop: VMOp::PushImm,
                    src: &src.to_le_bytes(),
                }
            }
            Code::Push_r64 => {
                let reg = instruction.op0_register();
                let src = VMReg::from(reg);
                VMCmd::PushReg {
                    vop: VMOp::PushReg,
                    src,
                }
            }
            Code::Pop_r64 => {
                let reg = instruction.op0_register();
                let dst = VMReg::from(reg);
                VMCmd::PopReg {
                    vop: VMOp::PopReg,
                    dst,
                }
            }
            Code::Mov_r8_imm8 => {
                let reg = instruction.op0_register();
                let bits = VMBits::from(reg);
                let dst = VMReg::from(reg);
                let src = instruction.immediate8();
                VMCmd::SetRegImm {
                    vop: VMOp::SetRegImm,
                    dbits: bits,
                    dst,
                    src: &src.to_le_bytes(),
                }
            }
            Code::Mov_r16_imm16 => {
                let reg = instruction.op0_register();
                let dst = VMReg::from(reg);
                let src = instruction.immediate16();
                VMCmd::SetRegImm {
                    vop: VMOp::SetRegImm,
                    dbits: VMBits::Lower16,
                    dst,
                    src: &src.to_le_bytes(),
                }
            }
            Code::Mov_r32_imm32 => {
                let reg = instruction.op0_register();
                let dst = VMReg::from(reg);
                let src = instruction.immediate32();
                VMCmd::SetRegImm {
                    vop: VMOp::SetRegImm,
                    dbits: VMBits::Lower32,
                    dst,
                    src: &src.to_le_bytes(),
                }
            }
            Code::Mov_r64_imm64 => {
                let reg = instruction.op0_register();
                let dst = VMReg::from(reg);
                let src = instruction.immediate64();
                VMCmd::SetRegImm {
                    vop: VMOp::SetRegImm,
                    dbits: VMBits::Lower64,
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
                        VMCmd::SetRegReg {
                            vop: VMOp::SetRegReg,
                            dbits,
                            dst,
                            sbits,
                            src,
                        }
                    }
                    OpKind::Memory => {
                        let src = VMMem::from(instruction);
                        VMCmd::SetRegMem {
                            vop: VMOp::SetRegMem,
                            dbits,
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
                        VMCmd::SetRegReg {
                            vop: VMOp::SetRegReg,
                            dbits,
                            dst,
                            sbits,
                            src,
                        }
                    }
                    OpKind::Memory => {
                        let dst = VMMem::from(instruction);
                        VMCmd::SetMemReg {
                            vop: VMOp::SetMemReg,
                            sbits,
                            dst,
                            src,
                        }
                    }
                    _ => return None,
                }
            }
            Code::Mov_rm64_imm32
            | Code::Mov_rm32_imm32
            | Code::Mov_rm16_imm16
            | Code::Mov_rm8_imm8 => {
                let (src, size) = match instruction.code() {
                    Code::Mov_rm8_imm8 => (instruction.immediate8() as i64, 1),
                    Code::Mov_rm16_imm16 => (instruction.immediate16() as i64, 2),
                    Code::Mov_rm32_imm32 => (instruction.immediate32() as i64, 4),
                    Code::Mov_rm64_imm32 => (instruction.immediate32to64() as i64, 8),
                    _ => unreachable!(),
                };

                match instruction.op0_kind() {
                    OpKind::Register => {
                        let reg = instruction.op0_register();
                        let bits = VMBits::from(reg);
                        let dst = VMReg::from(reg);
                        VMCmd::SetRegImm {
                            vop: VMOp::SetRegImm,
                            dbits: bits,
                            dst,
                            src: &src.to_le_bytes()[..size],
                        }
                    }
                    OpKind::Memory => {
                        let dst = VMMem::from(instruction);
                        VMCmd::SetMemImm {
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
                    OpKind::Immediate8 => (instruction.immediate8() as i64, 1),
                    OpKind::Immediate8to16 => (instruction.immediate8to16() as i64, 2),
                    OpKind::Immediate8to32 => (instruction.immediate8to32() as i64, 4),
                    OpKind::Immediate8to64 => (instruction.immediate8to64() as i64, 8),
                    _ => unreachable!(),
                };

                match instruction.op0_kind() {
                    OpKind::Register => {
                        let dreg = instruction.op0_register();
                        let dst = VMReg::from(dreg);
                        let dbits = VMBits::from(dreg);
                        VMCmd::AddSubRegImm {
                            vop: VMOp::AddSubRegImm,
                            dbits,
                            dst,
                            sub,
                            store,
                            src: &src.to_le_bytes()[..size],
                        }
                    }
                    OpKind::Memory => {
                        let dst = VMMem::from(instruction);
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
                let sub = matches!(instruction.mnemonic(), Mnemonic::Sub | Mnemonic::Cmp);
                let store = matches!(instruction.mnemonic(), Mnemonic::Add | Mnemonic::Sub);

                let src = instruction.immediate16();

                match instruction.op0_kind() {
                    OpKind::Register => {
                        let reg = instruction.op0_register();
                        let dst = VMReg::from(reg);
                        let bits = VMBits::from(reg);
                        VMCmd::AddSubRegImm {
                            vop: VMOp::AddSubRegImm,
                            dbits: bits,
                            dst,
                            sub,
                            store,
                            src: &src.to_le_bytes(),
                        }
                    }
                    OpKind::Memory => {
                        let dst = VMMem::from(instruction);
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
            Code::Add_rm64_imm32
            | Code::Add_rm32_imm32
            | Code::Sub_rm64_imm32
            | Code::Sub_rm32_imm32
            | Code::Cmp_rm64_imm32
            | Code::Cmp_rm32_imm32 => {
                let sub = matches!(instruction.mnemonic(), Mnemonic::Sub | Mnemonic::Cmp);
                let store = matches!(instruction.mnemonic(), Mnemonic::Add | Mnemonic::Sub);

                let (src, size) = match instruction.op1_kind() {
                    OpKind::Immediate32 => (instruction.immediate32() as i64, 4),
                    OpKind::Immediate32to64 => (instruction.immediate32to64() as i64, 8),
                    _ => unreachable!(),
                };

                match instruction.op0_kind() {
                    OpKind::Register => {
                        let reg = instruction.op0_register();
                        let dst = VMReg::from(reg);
                        let bits = VMBits::from(reg);
                        VMCmd::AddSubRegImm {
                            vop: VMOp::AddSubRegImm,
                            dbits: bits,
                            dst,
                            sub,
                            store,
                            src: &src.to_le_bytes()[..size],
                        }
                    }
                    OpKind::Memory => {
                        let dst = VMMem::from(instruction);
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
                    OpKind::Memory => {
                        let src = VMMem::from(instruction);
                        VMCmd::AddSubRegMem {
                            vop: VMOp::AddSubRegMem,
                            src,
                            sub,
                            store,
                            dbits,
                            dst,
                        }
                    }
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
                    OpKind::Memory => {
                        let dst = VMMem::from(instruction);
                        VMCmd::AddSubMemReg {
                            vop: VMOp::AddSubMemReg,
                            dst,
                            sub,
                            store,
                            sbits,
                            src,
                        }
                    }
                    _ => return None,
                }
            }
            Code::Lea_r16_m | Code::Lea_r32_m | Code::Lea_r64_m => {
                let reg = instruction.op0_register();
                let bits = VMBits::from(reg);
                let dst = VMReg::from(reg);
                let src = VMMem::from(instruction);

                VMCmd::SetRegMem {
                    vop: VMOp::SetRegMem,
                    dbits: bits,
                    load: false,
                    dst,
                    src,
                }
            }
            Code::Call_rel32_64 => {
                let dst = instruction.memory_displacement64().try_into().unwrap();
                VMCmd::BranchImm {
                    vop: VMOp::BranchImm,
                    ret: true,
                    dst,
                }
            }
            Code::Call_rm64 => match instruction.op0_kind() {
                OpKind::Register => VMCmd::BranchReg {
                    vop: VMOp::BranchReg,
                    ret: true,
                    dst: VMReg::from(instruction.op0_register()),
                },
                OpKind::Memory => VMCmd::BranchMem {
                    vop: VMOp::BranchMem,
                    ret: true,
                    dst: VMMem::from(instruction),
                },
                _ => return None,
            },
            Code::Jmp_rel8_64 | Code::Jmp_rel32_64 => {
                let dst = instruction.memory_displacement64().try_into().unwrap();
                VMCmd::BranchImm {
                    vop: VMOp::BranchImm,
                    ret: false,
                    dst,
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
                    dst: VMMem::from(instruction),
                    ret: false,
                },
                _ => return None,
            },
            Code::Ja_rel32_64 | Code::Ja_rel8_64 => {
                let dst = instruction.memory_displacement64().try_into().unwrap();
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
                let dst = instruction.memory_displacement64().try_into().unwrap();
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
                let dst = instruction.memory_displacement64().try_into().unwrap();
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
                let dst = instruction.memory_displacement64().try_into().unwrap();
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
                let dst = instruction.memory_displacement64().try_into().unwrap();
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
                let dst = instruction.memory_displacement64().try_into().unwrap();
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
                let dst = instruction.memory_displacement64().try_into().unwrap();
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
                let dst = instruction.memory_displacement64().try_into().unwrap();
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
                let dst = instruction.memory_displacement64().try_into().unwrap();
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
                let dst = instruction.memory_displacement64().try_into().unwrap();
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
                let dst = instruction.memory_displacement64().try_into().unwrap();
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
                let dst = instruction.memory_displacement64().try_into().unwrap();
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
                let dst = instruction.memory_displacement64().try_into().unwrap();
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
                let dst = instruction.memory_displacement64().try_into().unwrap();
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
                let dst = instruction.memory_displacement64().try_into().unwrap();
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
                let dst = instruction.memory_displacement64().try_into().unwrap();
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
            Code::Nopw
            | Code::Nopd
            | Code::Nopq
            | Code::Nop_rm16
            | Code::Nop_rm32
            | Code::Nop_rm64 => VMCmd::Nop { vop: VMOp::Nop },
            _ => {
                // println!("{instruction} -> {:?}", instruction.code());
                return None;
            }
        };

        vinstructions.extend_from_slice(&bytecode.encode(mapper));

        i += 1;
    }

    Some(vinstructions)
}
