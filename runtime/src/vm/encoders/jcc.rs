use rand::seq::SliceRandom;
use rand::Rng;
use strum::IntoEnumIterator;

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMCondition, VMFlag, VMLogic, VMOp, VMReg, VMTest};
use crate::vm::encoders::{Effect, Encode};

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
        match self.logic {
            VMLogic::SAND | VMLogic::SOR => vec![],
            _ => vec![Effect::Register(VMReg::NBranch)],
        }
    }
}

impl Jcc {
    pub fn jump() -> Self {
        let mut rng = rand::thread_rng();

        let logic = if rng.gen() {
            VMLogic::JAND
        } else {
            VMLogic::JOR
        };

        Self::always(logic)
    }

    pub fn call() -> Self {
        let mut rng = rand::thread_rng();

        let logic = if rng.gen() {
            VMLogic::CAND
        } else {
            VMLogic::COR
        };

        Self::always(logic)
    }

    fn always(logic: VMLogic) -> Self {
        let mut rng = rand::thread_rng();

        let flags = VMFlag::iter().collect::<Vec<VMFlag>>();
        let flag = flags.choose(&mut rng).unwrap();

        Self {
            logic,
            conditions: vec![VMCondition {
                test: VMTest::EQ,
                lhs: *flag as u8,
                rhs: *flag as u8,
            }],
        }
    }
}
