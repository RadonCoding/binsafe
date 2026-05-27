use iced_x86::{Code, Instruction, Mnemonic};

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMOp, VMReg};
use crate::vm::encoders::Encode;

pub struct PushPopRegs<'a> {
    pub pop: bool,
    pub seq: &'a [u8],
}

impl Encode for PushPopRegs<'_> {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = vec![mapper.index(VMOp::PushPopRegs)];
        bytes.push(self.pop as u8);
        bytes.push(self.seq.len() as u8);
        bytes.extend_from_slice(self.seq);
        bytes
    }
}

pub struct PushImm<'a> {
    pub src: &'a [u8],
}

impl Encode for PushImm<'_> {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = vec![mapper.index(VMOp::PushImm)];
        bytes.push(self.src.len() as u8);
        bytes.extend_from_slice(self.src);
        bytes
    }
}

pub struct PushReg {
    pub src: VMReg,
}

impl Encode for PushReg {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::PushReg), mapper.index(self.src)]
    }
}

pub struct PopReg {
    pub dst: VMReg,
}

impl Encode for PopReg {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(VMOp::PopReg), mapper.index(self.dst)]
    }
}

pub fn try_emit_push_pop_regs(
    mapper: &mut Mapper,
    instructions: &[Instruction],
) -> Option<(Vec<u8>, usize)> {
    let code = instructions[0].code();

    if code != Code::Push_r64 && code != Code::Pop_r64 {
        return None;
    }

    let mut seq = Vec::new();
    let mut j = 0;

    while j < instructions.len() && instructions[j].code() == code {
        let vreg = VMReg::from(instructions[j].op0_register());
        seq.push(mapper.index(vreg));
        j += 1;
    }

    if seq.len() < 2 {
        return None;
    }

    let pop = instructions[0].mnemonic() == Mnemonic::Pop;

    Some((PushPopRegs { pop, seq: &seq }.encode(mapper), j))
}

pub fn encode(mapper: &mut Mapper, instruction: &Instruction) -> Option<Vec<u8>> {
    let bytes = match instruction.code() {
        Code::Pushq_imm8 => PushImm {
            src: &instruction.immediate8().to_le_bytes(),
        }
        .encode(mapper),
        Code::Push_imm16 => PushImm {
            src: &instruction.immediate16().to_le_bytes(),
        }
        .encode(mapper),
        Code::Pushq_imm32 => PushImm {
            src: &instruction.immediate32().to_le_bytes(),
        }
        .encode(mapper),
        Code::Push_r64 => PushReg {
            src: VMReg::from(instruction.op0_register()),
        }
        .encode(mapper),
        Code::Pop_r64 => PopReg {
            dst: VMReg::from(instruction.op0_register()),
        }
        .encode(mapper),
        _ => return None,
    };

    Some(bytes)
}
