mod branch;

use crate::runtime::Runtime;
use crate::vm::encoders::Encode;
use crate::vm::transform::{Phase, Transform};

pub struct Mutation;

impl Transform for Mutation {
    fn phase(&self) -> Phase {
        Phase::Mutation
    }

    fn run(
        &self,
        _rt: &mut Runtime,
        operations: Vec<Box<dyn Encode>>,
        rng: &mut dyn rand::RngCore,
    ) -> Vec<Box<dyn Encode>> {
        let mut operations = operations;

        branch::mutate(&mut operations, rng);

        operations
    }
}
