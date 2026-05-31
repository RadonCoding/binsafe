use std::any::Any;
use std::rc::Rc;

use rand::seq::SliceRandom;
use rand::Rng;
use strum::IntoEnumIterator;

use crate::vm::bytecode::{VMCondition, VMFlag, VMLogic, VMTest};
use crate::vm::encoders::jcc::Jcc;
use crate::vm::encoders::Encode;

/// Replaces lift-time placeholders with randomized concrete forms, descending into children so the operations stay canonical until after deduplication.
pub fn diversify(operations: Vec<Rc<dyn Encode>>) -> Vec<Rc<dyn Encode>> {
    let mut operations = operations;
    let mut rng = rand::thread_rng();

    walk(&mut operations, &mut rng);

    operations
}

fn walk<R: Rng>(operations: &mut Vec<Rc<dyn Encode>>, rng: &mut R) {
    for op in operations.iter_mut() {
        if let Some(children) = Rc::get_mut(op).unwrap().children() {
            walk(children, rng);
            continue;
        }

        let logic = {
            let any: &dyn Any = &**op;
            any.downcast_ref::<Jcc>()
                .filter(|j| j.conditions.is_empty())
                .map(|j| j.logic)
        };

        let Some(logic) = logic else {
            continue;
        };

        let logic = match logic {
            VMLogic::JAND => {
                if rng.gen() {
                    VMLogic::JAND
                } else {
                    VMLogic::JOR
                }
            }
            VMLogic::CAND => {
                if rng.gen() {
                    VMLogic::CAND
                } else {
                    VMLogic::COR
                }
            }
            other => other,
        };

        let flags = VMFlag::iter().collect::<Vec<VMFlag>>();
        let flag = *flags.choose(rng).unwrap();

        *op = Rc::new(Jcc {
            logic,
            conditions: vec![VMCondition {
                test: VMTest::EQ,
                lhs: flag as u8,
                rhs: flag as u8,
            }],
        });
    }
}
