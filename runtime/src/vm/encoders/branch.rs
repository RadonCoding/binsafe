use iced_x86::{Code, Instruction, OpKind};

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMMem, VMOp, VMReg};
use crate::vm::encoders::Encode;

pub struct BranchImm {
    pub ret: bool,
    pub dst: u32,
}

impl Encode for BranchImm {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = vec![mapper.index(VMOp::BranchImm), self.ret as u8];
        bytes.extend_from_slice(&self.dst.to_le_bytes());
        bytes
    }
}

pub struct BranchReg {
    pub ret: bool,
    pub dst: VMReg,
}

impl Encode for BranchReg {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![
            mapper.index(VMOp::BranchReg),
            self.ret as u8,
            mapper.index(self.dst),
        ]
    }
}

pub struct BranchMem {
    pub ret: bool,
    pub dst: VMMem,
}

impl Encode for BranchMem {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = vec![mapper.index(VMOp::BranchMem), self.ret as u8];
        bytes.extend_from_slice(&self.dst.encode(mapper));
        bytes
    }
}

pub fn encode(mapper: &mut Mapper, instruction: &Instruction) -> Option<Vec<u8>> {
    let bytes = match instruction.code() {
        Code::Call_rel32_64 => BranchImm {
            ret: true,
            dst: instruction.memory_displacement64().try_into().unwrap(),
        }
        .encode(mapper),
        Code::Call_rm64 => match instruction.op0_kind() {
            OpKind::Register => BranchReg {
                ret: true,
                dst: VMReg::from(instruction.op0_register()),
            }
            .encode(mapper),
            OpKind::Memory => BranchMem {
                ret: true,
                dst: VMMem::from(instruction),
            }
            .encode(mapper),
            _ => return None,
        },
        Code::Jmp_rel8_64 | Code::Jmp_rel32_64 => BranchImm {
            ret: false,
            dst: instruction.memory_displacement64().try_into().unwrap(),
        }
        .encode(mapper),
        Code::Jmp_rm64 => match instruction.op0_kind() {
            OpKind::Register => BranchReg {
                ret: false,
                dst: VMReg::from(instruction.op0_register()),
            }
            .encode(mapper),
            OpKind::Memory => BranchMem {
                ret: false,
                dst: VMMem::from(instruction),
            }
            .encode(mapper),
            _ => return None,
        },
        _ => return None,
    };

    Some(bytes)
}
