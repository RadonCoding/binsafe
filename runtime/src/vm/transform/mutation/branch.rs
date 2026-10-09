use crate::vm::bytecode::{Flag, VMCondition, VMLogic};
use crate::vm::encoders::branch::Branch;
use crate::vm::encoders::Encode;
use crate::vm::transform::descend;
use rand::seq::SliceRandom;
use rand::Rng;
use strum::IntoEnumIterator;

/// Rewrites each [`Branch`] in place via randomized, semantics-preserving conditions.
pub fn mutate<R: Rng>(operations: &mut Vec<Box<dyn Encode>>, rng: &mut R) {
    descend(operations, |operations| {
        for i in 0..operations.len() {
            let Some(branch) = operations[i].as_any_mut().downcast_mut::<Branch>() else {
                continue;
            };

            let (and, or, xor) = match branch.logic {
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

            let is_always_true = branch.conditions.len() == 1
                && flags
                    .iter()
                    .any(|&f| branch.conditions[0] == VMCondition::eq(f, f));
            let is_always_false = branch.conditions.len() == 1
                && flags
                    .iter()
                    .any(|&f| branch.conditions[0] == VMCondition::neq(f, f));

            if is_always_true {
                let lhs = *flags.choose(rng).unwrap();
                let rhs = *flags.choose(rng).unwrap();

                let x = VMCondition::eq(lhs, rhs);
                let not_x = VMCondition::neq(lhs, rhs);

                match rng.gen_range(0..3) {
                    0 => {
                        // X XOR !X == 1.
                        branch.logic = xor;
                        branch.conditions = vec![x, not_x];

                        let remaining = rng.gen_range(0..=1);

                        if remaining == 1 {
                            let y = random(&flags, rng);
                            branch.conditions.push(y);
                            branch.conditions.push(y);
                        }
                    }
                    1 => {
                        // X OR !X == 1.
                        branch.logic = or;
                        branch.conditions = vec![x, not_x];

                        let count = rng.gen_range(0..=2);

                        for _ in 0..count {
                            branch.conditions.push(random(&flags, rng));
                        }
                    }
                    _ => {
                        // X AND 1 == X.
                        branch.logic = and;
                        branch.conditions = vec![VMCondition::eq(lhs, lhs)];

                        let count = rng.gen_range(0..=3);

                        for _ in 0..count {
                            let flag = *flags.choose(rng).unwrap();
                            branch.conditions.push(VMCondition::eq(flag, flag));
                        }
                    }
                }

                branch.conditions.shuffle(rng);
                continue;
            }

            if is_always_false {
                let lhs = *flags.choose(rng).unwrap();
                let rhs = *flags.choose(rng).unwrap();

                let x = VMCondition::eq(lhs, rhs);
                let not_x = VMCondition::neq(lhs, rhs);

                branch.logic = and;
                branch.conditions = vec![x, not_x];

                let count = rng.gen_range(0..=2);

                for _ in 0..count {
                    let flag = *flags.choose(rng).unwrap();
                    branch.conditions.push(VMCondition::eq(flag, flag));
                }

                branch.conditions.shuffle(rng);
                continue;
            }

            let remaining = 4usize.saturating_sub(branch.conditions.len());

            match branch.logic {
                VMLogic::JAND | VMLogic::CAND | VMLogic::SAND => {
                    // X AND 1 == X.
                    let count = rng.gen_range(0..=remaining);

                    for _ in 0..count {
                        let flag = *flags.choose(rng).unwrap();
                        branch.conditions.push(VMCondition::eq(flag, flag));
                    }

                    branch.logic = and;
                    branch.conditions.shuffle(rng);
                }
                VMLogic::JOR | VMLogic::COR | VMLogic::SOR => {
                    // X OR 0 == X.
                    let count = rng.gen_range(0..=remaining);

                    for _ in 0..count {
                        let flag = *flags.choose(rng).unwrap();
                        branch.conditions.push(VMCondition::neq(flag, flag));
                    }

                    branch.logic = or;
                    branch.conditions.shuffle(rng);
                }
                VMLogic::JXOR | VMLogic::CXOR | VMLogic::SXOR => {
                    // X XOR Y XOR Y == X.
                    let pairs = rng.gen_range(0..=(remaining / 2));

                    for _ in 0..pairs {
                        let y = random(&flags, rng);
                        branch.conditions.push(y);
                        branch.conditions.push(y);
                    }

                    branch.logic = xor;
                    branch.conditions.shuffle(rng);
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
