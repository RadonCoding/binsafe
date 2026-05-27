use iced_x86::{Code, Instruction, Mnemonic, OpKind};

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMBits, VMMem, VMOp, VMReg};
use crate::vm::encoders::Encode;

pub struct AddSubRegImm<'a> {
    pub dbits: VMBits,
    pub dst: VMReg,
    pub sub: bool,
    pub store: bool,
    pub src: &'a [u8],
}

impl Encode for AddSubRegImm<'_> {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = vec![
            mapper.index(VMOp::AddSubRegImm),
            mapper.index(self.dbits),
            mapper.index(self.dst),
            self.sub as u8,
            self.store as u8,
        ];
        bytes.extend_from_slice(self.src);
        bytes
    }
}

pub struct AddSubRegReg {
    pub dbits: VMBits,
    pub dst: VMReg,
    pub sbits: VMBits,
    pub src: VMReg,
    pub sub: bool,
    pub store: bool,
}

impl Encode for AddSubRegReg {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![
            mapper.index(VMOp::AddSubRegReg),
            mapper.index(self.dbits),
            mapper.index(self.dst),
            mapper.index(self.sbits),
            mapper.index(self.src),
            self.sub as u8,
            self.store as u8,
        ]
    }
}

pub struct AddSubRegMem {
    pub src: VMMem,
    pub sub: bool,
    pub store: bool,
    pub dbits: VMBits,
    pub dst: VMReg,
}

impl Encode for AddSubRegMem {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = vec![mapper.index(VMOp::AddSubRegMem)];
        bytes.extend_from_slice(&self.src.encode(mapper));
        bytes.push(self.sub as u8);
        bytes.push(self.store as u8);
        bytes.push(mapper.index(self.dbits));
        bytes.push(mapper.index(self.dst));
        bytes
    }
}

pub struct AddSubMemImm<'a> {
    pub dst: VMMem,
    pub sub: bool,
    pub store: bool,
    pub src: &'a [u8],
}

impl Encode for AddSubMemImm<'_> {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = vec![mapper.index(VMOp::AddSubMemImm)];
        bytes.extend_from_slice(&self.dst.encode(mapper));
        bytes.push(self.sub as u8);
        bytes.push(self.store as u8);
        bytes.push(self.src.len() as u8);
        bytes.extend_from_slice(self.src);
        bytes
    }
}

pub struct AddSubMemReg {
    pub dst: VMMem,
    pub sub: bool,
    pub store: bool,
    pub sbits: VMBits,
    pub src: VMReg,
}

impl Encode for AddSubMemReg {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = vec![mapper.index(VMOp::AddSubMemReg)];
        bytes.extend_from_slice(&self.dst.encode(mapper));
        bytes.push(self.sub as u8);
        bytes.push(self.store as u8);
        bytes.push(mapper.index(self.sbits));
        bytes.push(mapper.index(self.src));
        bytes
    }
}

pub fn encode(mapper: &mut Mapper, instruction: &Instruction) -> Option<Vec<u8>> {
    let code = instruction.code();
    let mnemonic = instruction.mnemonic();
    let sub = matches!(mnemonic, Mnemonic::Sub | Mnemonic::Cmp);
    let store = matches!(mnemonic, Mnemonic::Add | Mnemonic::Sub);

    let bytes = match code {
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
            let (src, size) = match instruction.op1_kind() {
                OpKind::Immediate8 => (instruction.immediate8() as i64, 1),
                OpKind::Immediate8to16 => (instruction.immediate8to16() as i64, 2),
                OpKind::Immediate8to32 => (instruction.immediate8to32() as i64, 4),
                OpKind::Immediate8to64 => (instruction.immediate8to64(), 8),
                _ => unreachable!(),
            };
            return encode_imm(mapper, instruction, sub, store, &src.to_le_bytes()[..size]);
        }
        Code::Add_rm16_imm16 | Code::Sub_rm16_imm16 | Code::Cmp_rm16_imm16 => {
            return encode_imm(
                mapper,
                instruction,
                sub,
                store,
                &instruction.immediate16().to_le_bytes(),
            );
        }
        Code::Add_rm64_imm32
        | Code::Add_rm32_imm32
        | Code::Sub_rm64_imm32
        | Code::Sub_rm32_imm32
        | Code::Cmp_rm64_imm32
        | Code::Cmp_rm32_imm32 => {
            let (src, size) = match instruction.op1_kind() {
                OpKind::Immediate32 => (instruction.immediate32() as i64, 4),
                OpKind::Immediate32to64 => (instruction.immediate32to64(), 8),
                _ => unreachable!(),
            };
            return encode_imm(mapper, instruction, sub, store, &src.to_le_bytes()[..size]);
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

            match instruction.op1_kind() {
                OpKind::Register => {
                    let sreg = instruction.op1_register();
                    AddSubRegReg {
                        dbits,
                        dst,
                        sbits: VMBits::from(sreg),
                        src: VMReg::from(sreg),
                        sub,
                        store,
                    }
                    .encode(mapper)
                }
                OpKind::Memory => AddSubRegMem {
                    src: VMMem::from(instruction),
                    sub,
                    store,
                    dbits,
                    dst,
                }
                .encode(mapper),
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

            match instruction.op0_kind() {
                OpKind::Register => {
                    let dreg = instruction.op0_register();
                    AddSubRegReg {
                        dbits: VMBits::from(dreg),
                        dst: VMReg::from(dreg),
                        sbits,
                        src,
                        sub,
                        store,
                    }
                    .encode(mapper)
                }
                OpKind::Memory => AddSubMemReg {
                    dst: VMMem::from(instruction),
                    sub,
                    store,
                    sbits,
                    src,
                }
                .encode(mapper),
                _ => return None,
            }
        }
        _ => return None,
    };

    Some(bytes)
}

fn encode_imm(
    mapper: &mut Mapper,
    instruction: &Instruction,
    sub: bool,
    store: bool,
    src: &[u8],
) -> Option<Vec<u8>> {
    let bytes = match instruction.op0_kind() {
        OpKind::Register => {
            let reg = instruction.op0_register();
            AddSubRegImm {
                dbits: VMBits::from(reg),
                dst: VMReg::from(reg),
                sub,
                store,
                src,
            }
            .encode(mapper)
        }
        OpKind::Memory => AddSubMemImm {
            dst: VMMem::from(instruction),
            sub,
            store,
            src,
        }
        .encode(mapper),
        _ => return None,
    };

    Some(bytes)
}
