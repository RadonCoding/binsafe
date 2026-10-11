mod branch;

use crate::runtime::Runtime;
use crate::vm::encoders::Encode;
use crate::vm::transform::{Phase, Transform};

pub struct Mutation;

impl Transform for Mutation {
    fn phase(&self) -> Phase {
        Phase::Mutation
    }

    fn run(&self, _rt: &mut Runtime, operations: Vec<Box<dyn Encode>>) -> Vec<Box<dyn Encode>> {
        let mut operations = operations;
        let mut rng = rand::thread_rng();

        branch::mutate(&mut operations, &mut rng);

        operations
    }
}
