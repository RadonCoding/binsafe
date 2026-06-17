use std::any::Any;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMReg, VMWidth};
use crate::vm::encoders::load_register::LoadRegister;
use crate::vm::encoders::store_register::StoreRegister;
use crate::vm::encoders::{Effect, Encode};
use crate::vm::transform::{Phase, Transform};

pub static PEEPHOLE_LOAD_STORE_COUNT: AtomicUsize = AtomicUsize::new(0);
pub static PEEPHOLE_STORE_LOAD_COUNT: AtomicUsize = AtomicUsize::new(0);

pub struct Peephole;

impl Transform for Peephole {
    fn phase(&self) -> Phase {
        Phase::Peephole
    }

    fn run(&self, _mapper: &mut Mapper, operations: Vec<Rc<dyn Encode>>) -> Vec<Rc<dyn Encode>> {
        let mut operations = operations;
        let mut changed = true;

        while changed {
            changed = false;
            let mut i = 0;

            while i + 1 < operations.len() {
                let opt_load = (&*operations[i] as &dyn Any).downcast_ref::<LoadRegister>();
                let opt_store = (&*operations[i + 1] as &dyn Any).downcast_ref::<StoreRegister>();

                if let (Some(load), Some(store)) = (opt_load, opt_store) {
                    if load.source == store.destination && load.width == store.width {
                        operations.drain(i..i + 2);
                        PEEPHOLE_LOAD_STORE_COUNT.fetch_add(2, Ordering::Relaxed);
                        changed = true;
                        continue;
                    }
                }

                let opt_store2 = (&*operations[i] as &dyn Any).downcast_ref::<StoreRegister>();
                let opt_load2 = (&*operations[i + 1] as &dyn Any).downcast_ref::<LoadRegister>();

                if let (Some(store), Some(load)) = (opt_store2, opt_load2) {
                    if store.destination == load.source && store.width == load.width {
                        if is_reg_dead(&operations, i + 2, store.destination) {
                            operations.drain(i..i + 2);
                            PEEPHOLE_STORE_LOAD_COUNT.fetch_add(2, Ordering::Relaxed);
                            changed = true;
                            continue;
                        }
                    }
                }

                i += 1;
            }
        }

        operations
    }
}

fn is_reg_dead(operations: &[Rc<dyn Encode>], start_idx: usize, reg: VMReg) -> bool {
    for op in &operations[start_idx..] {
        let reads = op
            .reads()
            .iter()
            .any(|e| matches!(e, Effect::Register(r) if *r == reg));
        let writes = op
            .writes()
            .iter()
            .any(|e| matches!(e, Effect::Register(r) if *r == reg));

        if reads {
            return false;
        }
        if writes {
            return true;
        }
    }
    false
}
