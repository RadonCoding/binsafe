use crate::vm::bytecode::{VMCondition, VMFlag, VMLogic};
use crate::vm::encoders::jcc::Jcc;
use crate::vm::encoders::Encode;
use crate::vm::transform::descend;
use rand::seq::SliceRandom;
use rand::Rng;
use strum::IntoEnumIterator;

/// Rewrites each [`Jcc`] in place via randomized, semantics-preserving conditions.
pub fn mutate<R: Rng>(operations: &mut Vec<Box<dyn Encode>>, rng: &mut R) {
    descend(operations, |operations| {
        for i in 0..operations.len() {
            let Some((logic, conditions)) = operations[i]
                .as_any()
                .downcast_ref::<Jcc>()
                .map(|jcc| (jcc.logic, jcc.conditions.clone()))
            else {
                continue;
            };

            let (and, or, xor) = match logic {
                VMLogic::JAND | VMLogic::JOR | VMLogic::JXOR => {
                    (VMLogic::JAND, VMLogic::JOR, VMLogic::JXOR)
                }
                VMLogic::CAND | VMLogic::COR | VMLogic::CXOR => {
                    (VMLogic::CAND, VMLogic::COR, VMLogic::CXOR)
                }
                VMLogic::SAND | VMLogic::SOR | VMLogic::SXOR => {
                    (VMLogic::SAND, VMLogic::SOR, VMLogic::SXOR)
                }
            };

            let flags = VMFlag::iter().collect::<Vec<VMFlag>>();

            let jcc = operations[i].as_any_mut().downcast_mut::<Jcc>().unwrap();

            if conditions.is_empty() {
                let lhs = *flags.choose(rng).unwrap();
                let rhs = *flags.choose(rng).unwrap();

                let x = VMCondition::eq(lhs, rhs);
                let not_x = VMCondition::neq(lhs, rhs);

                match rng.gen_range(0..3) {
                    0 => {
                        // X XOR !X == 1.
                        jcc.logic = xor;
                        jcc.conditions = vec![x, not_x];

                        let remaining = rng.gen_range(0..=1);

                        if remaining == 1 {
                            let y = random(&flags, rng);
                            jcc.conditions.push(y);
                            jcc.conditions.push(y);
                        }
                    }

                    1 => {
                        // X OR !X == 1.
                        jcc.logic = or;
                        jcc.conditions = vec![x, not_x];

                        let count = rng.gen_range(0..=2);

                        for _ in 0..count {
                            jcc.conditions.push(random(&flags, rng));
                        }
                    }

                    _ => {
                        // X AND 1 == X.
                        jcc.logic = and;
                        jcc.conditions = vec![VMCondition::eq(lhs, lhs)];

                        let count = rng.gen_range(0..=3);

                        for _ in 0..count {
                            let flag = *flags.choose(rng).unwrap();
                            jcc.conditions.push(VMCondition::eq(flag, flag));
                        }
                    }
                }

                jcc.conditions.shuffle(rng);
                continue;
            }

            let remaining = 4usize.saturating_sub(jcc.conditions.len());

            match logic {
                VMLogic::JXOR | VMLogic::CXOR | VMLogic::SXOR => {
                    // X XOR Y XOR Y == X.
                    let pairs = rng.gen_range(0..=(remaining / 2));

                    for _ in 0..pairs {
                        let y = random(&flags, rng);
                        jcc.conditions.push(y);
                        jcc.conditions.push(y);
                    }

                    jcc.logic = xor;
                    jcc.conditions.shuffle(rng);
                }

                VMLogic::JAND | VMLogic::CAND | VMLogic::SAND => {
                    // X AND 1 == X.
                    let count = rng.gen_range(0..=remaining);

                    for _ in 0..count {
                        let flag = *flags.choose(rng).unwrap();
                        jcc.conditions.push(VMCondition::eq(flag, flag));
                    }

                    jcc.logic = and;
                    jcc.conditions.shuffle(rng);
                }

                VMLogic::JOR | VMLogic::COR | VMLogic::SOR => {
                    // X OR 0 == X.
                    let count = rng.gen_range(0..=remaining);

                    for _ in 0..count {
                        let flag = *flags.choose(rng).unwrap();
                        jcc.conditions.push(VMCondition::cmp(flag, 1));
                    }

                    jcc.logic = or;
                    jcc.conditions.shuffle(rng);
                }
            }
        }
    });
}

/// Generates a randomized [`VMCondition`].
fn random<R: Rng>(flags: &[VMFlag], rng: &mut R) -> VMCondition {
    let lhs = *flags.choose(rng).unwrap();
    let rhs = *flags.choose(rng).unwrap();

    match rng.gen_range(0..3) {
        0 => VMCondition::eq(lhs, rhs),
        1 => VMCondition::neq(lhs, rhs),
        _ => VMCondition::cmp(lhs, rng.gen_range(0..=1)),
    }
}
