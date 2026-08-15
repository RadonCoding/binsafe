use crate::vm::bytecode::{Flag, VMCondition, VMLogic};
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
            let Some(jcc) = operations[i].as_any_mut().downcast_mut::<Jcc>() else {
                continue;
            };

            let (and, or, xor) = match jcc.logic {
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

            let flags = Flag::iter().collect::<Vec<Flag>>();

            let is_always_true = jcc.conditions.len() == 1
                && flags
                    .iter()
                    .any(|&f| jcc.conditions[0] == VMCondition::eq(f, f));
            let is_always_false = jcc.conditions.len() == 1
                && flags
                    .iter()
                    .any(|&f| jcc.conditions[0] == VMCondition::neq(f, f));

            if is_always_true {
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

            if is_always_false {
                let lhs = *flags.choose(rng).unwrap();
                let rhs = *flags.choose(rng).unwrap();

                let x = VMCondition::eq(lhs, rhs);
                let not_x = VMCondition::neq(lhs, rhs);

                jcc.logic = and;
                jcc.conditions = vec![x, not_x];

                let count = rng.gen_range(0..=2);

                for _ in 0..count {
                    let flag = *flags.choose(rng).unwrap();
                    jcc.conditions.push(VMCondition::eq(flag, flag));
                }

                jcc.conditions.shuffle(rng);
                continue;
            }

            let remaining = 4usize.saturating_sub(jcc.conditions.len());

            match jcc.logic {
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
            }
        }
    });
}

/// Generates a randomized [`VMCondition`].
fn random<R: Rng>(flags: &[Flag], rng: &mut R) -> VMCondition {
    let lhs = *flags.choose(rng).unwrap();
    let rhs = *flags.choose(rng).unwrap();

    match rng.gen_range(0..3) {
        0 => VMCondition::eq(lhs, rhs),
        1 => VMCondition::neq(lhs, rhs),
        _ => VMCondition::cmp(lhs, rng.gen_range(0..=1)),
    }
}
