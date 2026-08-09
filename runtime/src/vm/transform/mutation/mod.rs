mod jcc;

use crate::mapper::Mapper;
use crate::vm::encoders::Encode;
use crate::vm::transform::{Phase, Transform};

pub struct Mutation;

impl Transform for Mutation {
    fn phase(&self) -> Phase {
        Phase::Mutation
    }

    fn run(&self, _mapper: &mut Mapper, operations: Vec<Box<dyn Encode>>) -> Vec<Box<dyn Encode>> {
        let mut operations = operations;
        let mut rng = rand::thread_rng();

        jcc::walk(&mut operations, &mut rng);

        operations
    }
}
