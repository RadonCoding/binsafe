use std::rc::Rc;

use crate::mapper::Mapper;
use crate::vm::encoders::load_register::LoadRegister;
use crate::vm::encoders::store_register::StoreRegister;
use crate::vm::encoders::Encode;
use crate::vm::transform::{downcast, overwritten, Phase, Transform};

pub struct Peephole;

impl Transform for Peephole {
    fn phase(&self) -> Phase {
        Phase::Peephole
    }

    fn run(
        &self,
        _mapper: &mut Mapper,
        mut operations: Vec<Rc<dyn Encode>>,
    ) -> Vec<Rc<dyn Encode>> {
        optimize(&mut operations);
        operations
    }
}

/// Optimizes load and store sequences by eliminating redundant register round-trips.
fn optimize(operations: &mut Vec<Rc<dyn Encode>>) {
    let mut index = 0;

    while index + 1 < operations.len() {
        if let (Some(load), Some(store)) = (
            downcast::<LoadRegister>(&operations[index]),
            downcast::<StoreRegister>(&operations[index + 1]),
        ) {
            if load.source == store.destination && load.width == store.width {
                operations.drain(index..index + 2);
                continue;
            }
        }

        if let (Some(store), Some(load)) = (
            downcast::<StoreRegister>(&operations[index]),
            downcast::<LoadRegister>(&operations[index + 1]),
        ) {
            if store.destination == load.source && store.width == load.width {
                if overwritten(&operations[index + 2..], store.destination) {
                    operations.drain(index..index + 2);
                    continue;
                }
            }
        }

        index += 1;
    }
}
