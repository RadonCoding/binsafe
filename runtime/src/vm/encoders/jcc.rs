use std::mem;

use rand::seq::SliceRandom;
use rand::Rng;

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
        AND,
        OR,
        NAND,
        NOR
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
    pub destination: u32,
}

impl Jcc {
    fn mutate(&mut self) {
        let mut rng = rand::thread_rng();

        self.conditions.shuffle(&mut rng);

        for condition in &mut self.conditions {
            match condition.test {
                VMTest::EQ | VMTest::NEQ if rng.gen() => {
                    mem::swap(&mut condition.lhs, &mut condition.rhs);
                }

                _ => {}
            }
        }

        self.conditions.shuffle(&mut rng);
    }
}
impl Encode for Jcc {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
        self.mutate();

        let mut bytes = vec![
            mapper.index(VMOp::Jcc),
            mapper.index(self.logic),
            self.conditions.len() as u8,
        ];

        for condition in &mut self.conditions {
            bytes.extend_from_slice(&condition.encode(mapper));
        }
        bytes.extend_from_slice(&self.destination.to_le_bytes());
        bytes
    }

    fn reads(&self) -> Vec<super::Effect> {
        vec![Effect::Flags]
    }

    fn writes(&self) -> Vec<super::Effect> {
        vec![Effect::Reg(VMReg::NBranch)]
    }
}
