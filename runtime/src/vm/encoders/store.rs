use iced_x86::{Code, Instruction};

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMBits, VMMem, VMOp, VMReg};
use crate::vm::encoders::Encode;

pub struct SetMemImm<'a> {
    pub dst: VMMem,
    pub src: &'a [u8],
}

impl Encode for SetMemImm<'_> {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = vec![mapper.index(VMOp::SetMemImm)];
        bytes.extend_from_slice(&self.dst.encode(mapper));
        bytes.push(self.src.len() as u8);
        bytes.extend_from_slice(self.src);
        bytes
    }
}

pub struct SetMemReg {
    pub sbits: VMBits,
    pub dst: VMMem,
    pub src: VMReg,
}

impl Encode for SetMemReg {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = vec![mapper.index(VMOp::SetMemReg), mapper.index(self.sbits)];
        bytes.extend_from_slice(&self.dst.encode(mapper));
        bytes.push(mapper.index(self.src));
        bytes
    }
}

pub fn encode(mapper: &mut Mapper, instruction: &Instruction) -> Option<Vec<u8>> {
    let code = instruction.code();

    let bytes = match code {
        Code::Mov_rm64_r64 | Code::Mov_rm32_r32 | Code::Mov_rm16_r16 | Code::Mov_rm8_r8 => {
            let sreg = instruction.op1_register();
            SetMemReg {
                sbits: VMBits::from(sreg),
                dst: VMMem::from(instruction),
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
            SetMemImm {
                dst: VMMem::from(instruction),
                src: &src.to_le_bytes()[..size],
            }
            .encode(mapper)
        }
        _ => return None,
    };

    Some(bytes)
}
