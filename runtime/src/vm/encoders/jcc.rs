use iced_x86::{Code, Instruction};

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMCond, VMFlag, VMLogic, VMOp, VMTest};
use crate::vm::encoders::Encode;

pub struct Jcc {
    pub logic: VMLogic,
    pub conds: Vec<VMCond>,
    pub dst: u32,
}

impl Encode for Jcc {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = vec![
            mapper.index(VMOp::Jcc),
            mapper.index(self.logic),
            self.conds.len() as u8,
        ];

        for cond in &self.conds {
            bytes.extend_from_slice(&cond.encode(mapper));
        }
        bytes.extend_from_slice(&self.dst.to_le_bytes());
        bytes
    }
}

pub fn encode(mapper: &mut Mapper, instruction: &Instruction) -> Option<Vec<u8>> {
    let dst: u32 = instruction.memory_displacement64().try_into().unwrap();

    let (logic, conds) = match instruction.code() {
        // JA = CF=0 AND ZF=0
        Code::Ja_rel32_64 | Code::Ja_rel8_64 => (
            VMLogic::AND,
            vec![cmp(VMFlag::Carry, 0), cmp(VMFlag::Zero, 0)],
        ),
        // JAE = CF=0
        Code::Jae_rel32_64 | Code::Jae_rel8_64 => (VMLogic::AND, vec![cmp(VMFlag::Carry, 0)]),
        // JB = CF=1
        Code::Jb_rel32_64 | Code::Jb_rel8_64 => (VMLogic::AND, vec![cmp(VMFlag::Carry, 1)]),
        // JBE = CF=1 OR ZF=1
        Code::Jbe_rel32_64 | Code::Jbe_rel8_64 => (
            VMLogic::OR,
            vec![cmp(VMFlag::Carry, 1), cmp(VMFlag::Zero, 1)],
        ),
        // JE = ZF=1
        Code::Je_rel32_64 | Code::Je_rel8_64 => (VMLogic::AND, vec![cmp(VMFlag::Zero, 1)]),
        // JG = ZF=0 AND SF=OF
        Code::Jg_rel32_64 | Code::Jg_rel8_64 => (
            VMLogic::AND,
            vec![cmp(VMFlag::Zero, 0), eq(VMFlag::Sign, VMFlag::Overflow)],
        ),
        // JGE = SF=OF
        Code::Jge_rel32_64 | Code::Jge_rel8_64 => {
            (VMLogic::AND, vec![eq(VMFlag::Sign, VMFlag::Overflow)])
        }
        // JL = SF<>OF
        Code::Jl_rel32_64 | Code::Jl_rel8_64 => {
            (VMLogic::AND, vec![neq(VMFlag::Sign, VMFlag::Overflow)])
        }
        // JLE = ZF=1 OR SF<>OF
        Code::Jle_rel32_64 | Code::Jle_rel8_64 => (
            VMLogic::OR,
            vec![cmp(VMFlag::Zero, 1), neq(VMFlag::Sign, VMFlag::Overflow)],
        ),
        // JNE = ZF=0
        Code::Jne_rel32_64 | Code::Jne_rel8_64 => (VMLogic::AND, vec![cmp(VMFlag::Zero, 0)]),
        // JNO = OF=0
        Code::Jno_rel32_64 | Code::Jno_rel8_64 => (VMLogic::AND, vec![cmp(VMFlag::Overflow, 0)]),
        // JNP = PF=0
        Code::Jnp_rel32_64 | Code::Jnp_rel8_64 => (VMLogic::AND, vec![cmp(VMFlag::Parity, 0)]),
        // JNS = SF=0
        Code::Jns_rel32_64 | Code::Jns_rel8_64 => (VMLogic::AND, vec![cmp(VMFlag::Sign, 0)]),
        // JO = OF=1
        Code::Jo_rel32_64 | Code::Jo_rel8_64 => (VMLogic::AND, vec![cmp(VMFlag::Overflow, 1)]),
        // JP = PF=1
        Code::Jp_rel32_64 | Code::Jp_rel8_64 => (VMLogic::AND, vec![cmp(VMFlag::Parity, 1)]),
        // JS = SF=1
        Code::Js_rel32_64 | Code::Js_rel8_64 => (VMLogic::AND, vec![cmp(VMFlag::Sign, 1)]),
        _ => return None,
    };

    Some(Jcc { logic, conds, dst }.encode(mapper))
}

fn cmp(lhs: VMFlag, rhs: u8) -> VMCond {
    VMCond {
        cmp: VMTest::CMP,
        lhs: lhs as u8,
        rhs,
    }
}

fn eq(lhs: VMFlag, rhs: VMFlag) -> VMCond {
    VMCond {
        cmp: VMTest::EQ,
        lhs: lhs as u8,
        rhs: rhs as u8,
    }
}

fn neq(lhs: VMFlag, rhs: VMFlag) -> VMCond {
    VMCond {
        cmp: VMTest::NEQ,
        lhs: lhs as u8,
        rhs: rhs as u8,
    }
}
