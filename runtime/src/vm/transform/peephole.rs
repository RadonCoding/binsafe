use crate::mapper::Mapper;
use crate::vm::encoders::load_register::LoadRegister;
use crate::vm::encoders::store_register::StoreRegister;
use crate::vm::encoders::Encode;
use crate::vm::transform::{overwritten, Phase, Transform};

pub struct Peephole;

impl Transform for Peephole {
    fn phase(&self) -> Phase {
        Phase::Peephole
    }

    fn run(
        &self,
        _mapper: &mut Mapper,
        mut operations: Vec<Box<dyn Encode>>,
    ) -> Vec<Box<dyn Encode>> {
        optimize(&mut operations);
        operations
    }
}

/// Optimizes [`LoadRegister`] and [`StoreRegister`] sequences by eliminating redundant register round-trips.
fn optimize(operations: &mut Vec<Box<dyn Encode>>) {
    let mut index = 0;

    while index + 1 < operations.len() {
        if let Some(children) = operations[index].children_mut() {
            optimize(children);
        }

        if let (Some(load), Some(store)) = (
            operations[index].as_any().downcast_ref::<LoadRegister>(),
            operations[index + 1]
                .as_any()
                .downcast_ref::<StoreRegister>(),
        ) {
            if load.source == store.destination && load.width == store.width {
                operations.drain(index..index + 2);
                continue;
            }
        }

        if let (Some(store), Some(load)) = (
            operations[index].as_any().downcast_ref::<StoreRegister>(),
            operations[index + 1]
                .as_any()
                .downcast_ref::<LoadRegister>(),
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
