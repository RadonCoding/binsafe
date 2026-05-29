use crate::mapper::{mapped, Mapper};
use crate::vm::bytecode::{VMOp, VMReg};
use crate::vm::encoders::{Effect, Encode};

mapped! {
    VMTest {
        CMP,
        EQ,
        NEQ,
    }
}

mapped! {
    VMLogic {
        JAND, // JUMP AND
        JOR, // JUMP OR

        CAND, // CALL AND
        COR,// CALL OR
    }
}

#[derive(Debug, Clone)]
pub struct VMCondition {
    pub test: VMTest,
    pub lhs: u8,
    pub rhs: u8,
}

impl Encode for VMCondition {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(self.test), self.lhs, self.rhs]
    }
}

#[derive(Debug)]
pub struct Jcc {
    pub logic: VMLogic,
    pub conditions: Vec<VMCondition>,
}

impl Encode for Jcc {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = vec![
            mapper.index(VMOp::Jcc),
            mapper.index(self.logic),
            self.conditions.len() as u8,
        ];

        for condition in &mut self.conditions {
            bytes.extend_from_slice(&condition.encode(mapper));
        }
        bytes
    }

    fn reads(&self) -> Vec<super::Effect> {
        vec![Effect::Flags, Effect::Scratch]
    }

    fn writes(&self) -> Vec<super::Effect> {
        vec![Effect::Register(VMReg::NBranch)]
    }
}
