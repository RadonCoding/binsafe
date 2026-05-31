use crate::mapper::Mapper;
use crate::vm::bytecode::{VMCondition, VMLogic, VMOp, VMReg};
use crate::vm::encoders::{Effect, Encode};

#[derive(Debug)]
pub struct Jcc {
    pub logic: VMLogic,
    pub conditions: Vec<VMCondition>,
}

impl Encode for Jcc {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = vec![
            mapper.index(VMOp::Jcc),
            mapper.index(self.logic),
            self.conditions.len() as u8,
        ];

        for condition in &self.conditions {
            bytes.extend_from_slice(&condition.encode(mapper));
        }
        bytes
    }

    fn reads(&self) -> Vec<super::Effect> {
        vec![Effect::Register(VMReg::Flags)]
    }

    fn writes(&self) -> Vec<super::Effect> {
        match self.logic {
            VMLogic::SAND | VMLogic::SOR => vec![],
            _ => vec![Effect::Register(VMReg::NBranch)],
        }
    }

    fn depth(&self) -> i32 {
        -1
    }

    fn branches(&self) -> bool {
        true
    }
}

impl Jcc {
    pub fn jump() -> Self {
        Self::always(VMLogic::JAND)
    }

    pub fn call() -> Self {
        Self::always(VMLogic::CAND)
    }

    fn always(logic: VMLogic) -> Self {
        Self {
            logic,
            conditions: vec![],
        }
    }
}
