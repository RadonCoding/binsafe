use std::mem;

use crate::{
    mapper::Mapper,
    vm::{
        bytecode::{Phase, VMWidth},
        encoders::{dispatch::Dispatch, load_immediate::LoadImmediate, Encode},
        transform::Transform,
    },
};

pub struct Indirect;

impl Transform for Indirect {
    fn phase(&self) -> Phase {
        Phase::Indirect
    }

    fn run(
        &self,
        mapper: &mut Mapper,
        mut operations: Vec<Box<dyn Encode>>,
    ) -> Vec<Box<dyn Encode>> {
        indirect(mapper, &mut operations);
        operations
    }
}

/// Redirects operations to use an indirect dispatch via [`Dispatch`].
fn indirect(mapper: &mut Mapper, operations: &mut Vec<Box<dyn Encode>>) {
    let mut index = 0;

    while index < operations.len() {
        if let Some(children) = operations[index].children_mut() {
            indirect(mapper, children);
        }

        let Some(op) = operations[index].op() else {
            index += 1;
            continue;
        };

        let operation = mem::replace(
            &mut operations[index],
            Box::new(LoadImmediate {
                width: VMWidth::Lower8,
                source: mapper.index(op).to_le_bytes().to_vec(),
            }),
        );

        index += 1;

        operations.insert(index, Box::new(Dispatch { operation }));

        index += 1;
    }
}
