use rand::seq::SliceRandom;

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMCondition, VMLogic, VMOp};
use crate::vm::encoders::Encode;

#[derive(Debug)]
pub struct Jcc {
    pub logic: VMLogic,
    pub conditions: Vec<VMCondition>,
    pub destination: u32,
}

impl Encode for Jcc {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        self.conditions.shuffle(&mut rng);

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
}
