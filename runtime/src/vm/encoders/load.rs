use iced_x86::{Code, Instruction, OpKind};

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMBits, VMMem, VMOp, VMReg};
use crate::vm::encoders::Encode;

pub struct SetRegImm<'a> {
    pub dbits: VMBits,
    pub dst: VMReg,
    pub src: &'a [u8],
}

impl Encode for SetRegImm<'_> {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = vec![
            mapper.index(VMOp::SetRegImm),
            mapper.index(self.dbits),
            mapper.index(self.dst),
        ];
        bytes.extend_from_slice(self.src);
        bytes
    }
}

pub struct SetRegReg {
    pub dbits: VMBits,
    pub dst: VMReg,
    pub sbits: VMBits,
    pub src: VMReg,
}

impl Encode for SetRegReg {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![
            mapper.index(VMOp::SetRegReg),
            mapper.index(self.dbits),
            mapper.index(self.dst),
            mapper.index(self.sbits),
            mapper.index(self.src),
        ]
    }
}

pub struct SetRegMem {
    pub dbits: VMBits,
    pub load: bool,
    pub dst: VMReg,
    pub src: VMMem,
}

impl Encode for SetRegMem {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = vec![
            mapper.index(VMOp::SetRegMem),
            mapper.index(self.dbits),
            self.load as u8,
            mapper.index(self.dst),
        ];
        bytes.extend_from_slice(&self.src.encode(mapper));
        bytes
    }
}

pub fn encode(mapper: &mut Mapper, instruction: &Instruction) -> Option<Vec<u8>> {
    let code = instruction.code();

    let bytes = match code {
        Code::Mov_r8_imm8 => {
            let reg = instruction.op0_register();
            SetRegImm {
                dbits: VMBits::from(reg),
                dst: VMReg::from(reg),
                src: &instruction.immediate8().to_le_bytes(),
            }
            .encode(mapper)
        }
        Code::Mov_r16_imm16 => SetRegImm {
            dbits: VMBits::Lower16,
            dst: VMReg::from(instruction.op0_register()),
            src: &instruction.immediate16().to_le_bytes(),
        }
        .encode(mapper),
        Code::Mov_r32_imm32 => SetRegImm {
            dbits: VMBits::Lower32,
            dst: VMReg::from(instruction.op0_register()),
            src: &instruction.immediate32().to_le_bytes(),
        }
        .encode(mapper),
        Code::Mov_r64_imm64 => SetRegImm {
            dbits: VMBits::Lower64,
            dst: VMReg::from(instruction.op0_register()),
            src: &instruction.immediate64().to_le_bytes(),
        }
        .encode(mapper),
        Code::Mov_r64_rm64 | Code::Mov_r32_rm32 | Code::Mov_r16_rm16 | Code::Mov_r8_rm8 => {
            let dreg = instruction.op0_register();
            let dbits = VMBits::from(dreg);
            let dst = VMReg::from(dreg);

            match instruction.op1_kind() {
                OpKind::Register => {
                    let sreg = instruction.op1_register();
                    SetRegReg {
                        dbits,
                        dst,
                        sbits: VMBits::from(sreg),
                        src: VMReg::from(sreg),
                    }
                    .encode(mapper)
                }
                OpKind::Memory => SetRegMem {
                    dbits,
                    load: true,
                    dst,
                    src: VMMem::from(instruction),
                }
                .encode(mapper),
                _ => return None,
            }
        }
        Code::Mov_rm64_r64 | Code::Mov_rm32_r32 | Code::Mov_rm16_r16 | Code::Mov_rm8_r8 => {
            let dreg = instruction.op0_register();
            let sreg = instruction.op1_register();
            SetRegReg {
                dbits: VMBits::from(dreg),
                dst: VMReg::from(dreg),
                sbits: VMBits::from(sreg),
                src: VMReg::from(sreg),
            }
            .encode(mapper)
        }
        Code::Mov_rm64_imm32 | Code::Mov_rm32_imm32 | Code::Mov_rm16_imm16 | Code::Mov_rm8_imm8 => {
            let (src, size) = match code {
                Code::Mov_rm8_imm8 => (instruction.immediate8() as i64, 1),
                Code::Mov_rm16_imm16 => (instruction.immediate16() as i64, 2),
                Code::Mov_rm32_imm32 => (instruction.immediate32() as i64, 4),
                Code::Mov_rm64_imm32 => (instruction.immediate32to64(), 8),
                _ => unreachable!(),
            };
            let reg = instruction.op0_register();
            SetRegImm {
                dbits: VMBits::from(reg),
                dst: VMReg::from(reg),
                src: &src.to_le_bytes()[..size],
            }
            .encode(mapper)
        }
        Code::Lea_r16_m | Code::Lea_r32_m | Code::Lea_r64_m => {
            let reg = instruction.op0_register();
            SetRegMem {
                dbits: VMBits::from(reg),
                load: false,
                dst: VMReg::from(reg),
                src: VMMem::from(instruction),
            }
            .encode(mapper)
        }
        _ => return None,
    };

    Some(bytes)
}
