use crate::mapper::Mapper;
use crate::vm::bytecode::VMCode;
use crate::vm::encoders::{Effect, Encode};
use std::any::Any;

#[derive(Debug)]
pub struct Compound {
    pub index: u8,
    pub members: Vec<Box<dyn Encode>>,
}

impl Compound {
    fn simulate(&self) -> (i32, i32) {
        let mut depth = 0;
        let mut low = 0;

        for operation in &self.members {
            depth -= operation.consumes();
            low = low.min(depth);
            depth += operation.produces();
        }

        (depth, low)
    }
}

impl Encode for Compound {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn code(&self) -> Option<VMCode> {
        Some(VMCode::Compound)
    }

    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = vec![self.index];

        for member in &self.members {
            bytes.extend(member.encode(mapper));
        }

        bytes
    }

    fn reads(&self) -> Vec<Effect> {
        self.members
            .iter()
            .flat_map(|member| member.reads())
            .collect()
    }

    fn writes(&self) -> Vec<Effect> {
        self.members
            .iter()
            .flat_map(|member| member.writes())
            .collect()
    }

    fn consumes(&self) -> i32 {
        let (_, low) = self.simulate();
        -low
    }

    fn produces(&self) -> i32 {
        let (depth, low) = self.simulate();
        depth - low
    }

    fn seal(&mut self, mapper: &mut Mapper, transform: &mut dyn FnMut(&mut [u8], usize)) {
        for member in &mut self.members {
            member.seal(mapper, transform);
        }
    }
}
