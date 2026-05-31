use std::any::Any;
use std::rc::Rc;

use rand::seq::SliceRandom;
use rand::Rng;
use strum::IntoEnumIterator;

use crate::vm::bytecode::{VMCondition, VMFlag, VMLogic, VMTest};
use crate::vm::encoders::jcc::Jcc;
use crate::vm::encoders::Encode;

/// Rewrites operations into logically equivalent randomized forms, descending into children.
pub fn mutate(operations: Vec<Rc<dyn Encode>>) -> Vec<Rc<dyn Encode>> {
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

        let jcc = {
            let any: &dyn Any = &**op;
            any.downcast_ref::<Jcc>()
                .map(|j| (j.logic, j.conditions.clone()))
        };

        let Some((logic, conditions)) = jcc else {
            continue;
        };

        let (logic, conditions) = if conditions.is_empty() {
            match logic {
                VMLogic::JAND => opaque(rng, VMLogic::JOR, VMLogic::JXOR),
                VMLogic::CAND => opaque(rng, VMLogic::COR, VMLogic::CXOR),
                VMLogic::SAND => opaque(rng, VMLogic::SOR, VMLogic::SXOR),
                VMLogic::JOR | VMLogic::COR | VMLogic::SOR => (logic, or_predicate(rng)),
                VMLogic::JXOR | VMLogic::CXOR | VMLogic::SXOR => (logic, xor_predicate(rng)),
            }
        } else {
            (logic, mutated(rng, logic, conditions))
        };

        *op = Rc::new(Jcc { logic, conditions });
    }
}

/// Expands each sub-condition through [`rewritten`] and appends fold-specific filler, then shuffles.
fn mutated<R: Rng>(rng: &mut R, logic: VMLogic, conditions: Vec<VMCondition>) -> Vec<VMCondition> {
    let mut conditions = conditions;

    match logic {
        VMLogic::JAND | VMLogic::CAND | VMLogic::SAND => {
            let mut i = 0;

            while i < conditions.len() {
                let rewrites = rewritten(&conditions[i]);

                if !rewrites.is_empty() && rng.gen() {
                    let chosen = rewrites.choose(rng).cloned().unwrap();
                    let length = chosen.len();
                    conditions.splice(i..i + 1, chosen);
                    i += length;
                } else {
                    i += 1;
                }
            }
        }
        VMLogic::JXOR | VMLogic::CXOR | VMLogic::SXOR => {
            for _ in 0..rng.gen_range(0..=1) {
                conditions.extend(neutral_pair(rng));
            }
        }
        _ => {}
    }

    conditions.shuffle(rng);
    conditions
}

/// Logically equivalent expansions of a sub-condition derived from x86 flag invariants.
fn rewritten(condition: &VMCondition) -> Vec<Vec<VMCondition>> {
    let zero = VMFlag::Zero as u8;
    let parity = VMFlag::Parity as u8;
    let sign = VMFlag::Sign as u8;

    match (condition.test, condition.lhs, condition.rhs) {
        (VMTest::CMP, lhs, 1) if lhs == zero => vec![
            vec![
                VMCondition {
                    test: VMTest::CMP,
                    lhs: sign,
                    rhs: 0,
                },
                VMCondition {
                    test: VMTest::NEQ,
                    lhs: zero,
                    rhs: sign,
                },
            ],
            vec![
                VMCondition {
                    test: VMTest::CMP,
                    lhs: parity,
                    rhs: 1,
                },
                VMCondition {
                    test: VMTest::EQ,
                    lhs: zero,
                    rhs: parity,
                },
            ],
        ],
        (VMTest::CMP, lhs, 1) if lhs == sign => vec![vec![
            VMCondition {
                test: VMTest::CMP,
                lhs: zero,
                rhs: 0,
            },
            VMCondition {
                test: VMTest::NEQ,
                lhs: sign,
                rhs: zero,
            },
        ]],
        _ => vec![],
    }
}

/// Builds a tautologically-true predicate by picking between the OR and XOR families and composing its sub-conditions accordingly.
fn opaque<R: Rng>(rng: &mut R, or: VMLogic, xor: VMLogic) -> (VMLogic, Vec<VMCondition>) {
    if rng.gen() {
        (or, or_predicate(rng))
    } else {
        (xor, xor_predicate(rng))
    }
}

/// Composes a tautologically-true predicate from a [`tautology`] block optionally compounded with a second one, each of which folds to true under OR.
fn or_predicate<R: Rng>(rng: &mut R) -> Vec<VMCondition> {
    let mut conditions = tautology(rng);
    if rng.gen() {
        conditions.extend(tautology(rng));
    }
    conditions.shuffle(rng);
    conditions
}

/// Composes a tautologically-true predicate from a [`tautology`] block optionally compounded with a [`neutral_pair`] that keeps the XOR fold odd.
fn xor_predicate<R: Rng>(rng: &mut R) -> Vec<VMCondition> {
    let mut conditions = tautology(rng);
    if rng.gen() {
        conditions.extend(neutral_pair(rng));
    }
    conditions.shuffle(rng);
    conditions
}

/// One of three tautological sub-condition shapes whose runtime-true count is always odd, so OR yields true and XOR contributes parity 1.
fn tautology<R: Rng>(rng: &mut R) -> Vec<VMCondition> {
    match rng.gen_range(0..3) {
        0 => cmp_pair(rng).to_vec(),
        1 => eq_pair(rng).to_vec(),
        _ => triple_eq(rng).to_vec(),
    }
}

/// Batch of sub-conditions whose combined XOR contribution is zero,
/// drawn from either a self-cancelling duplicate of an arbitrary single condition or, less often, a pair of [`tautology`] blocks.
fn neutral_pair<R: Rng>(rng: &mut R) -> Vec<VMCondition> {
    if rng.gen_ratio(1, 3) {
        let mut conditions = tautology(rng);
        conditions.extend(tautology(rng));
        conditions
    } else {
        let condition = condition(rng);
        vec![condition.clone(), condition]
    }
}

/// Pair of sub-conditions comparing the same randomly chosen flag's bit against both possible values, exactly one of which evaluates true at runtime.
fn cmp_pair<R: Rng>(rng: &mut R) -> [VMCondition; 2] {
    let flag = pick(rng);
    [
        VMCondition {
            test: VMTest::CMP,
            lhs: flag,
            rhs: 0,
        },
        VMCondition {
            test: VMTest::CMP,
            lhs: flag,
            rhs: 1,
        },
    ]
}

/// Pair of sub-conditions testing equality and inequality of two distinct randomly chosen flag bits, exactly one of which evaluates true at runtime.
fn eq_pair<R: Rng>(rng: &mut R) -> [VMCondition; 2] {
    let [a, b] = pick_two(rng);
    [
        VMCondition {
            test: VMTest::EQ,
            lhs: a,
            rhs: b,
        },
        VMCondition {
            test: VMTest::NEQ,
            lhs: a,
            rhs: b,
        },
    ]
}

/// Three pairwise equality and inequality sub-conditions over three distinct randomly chosen flag bits,
/// drawn from four rotations that each force an odd number of trues by pigeonhole or the contrapositive of transitivity.
fn triple_eq<R: Rng>(rng: &mut R) -> [VMCondition; 3] {
    let [a, b, c] = pick_three(rng);
    let eq = |lhs, rhs| VMCondition {
        test: VMTest::EQ,
        lhs,
        rhs,
    };
    let neq = |lhs, rhs| VMCondition {
        test: VMTest::NEQ,
        lhs,
        rhs,
    };
    match rng.gen_range(0..4) {
        0 => [eq(a, b), eq(b, c), eq(a, c)],
        1 => [eq(a, b), neq(b, c), neq(a, c)],
        2 => [neq(a, b), eq(b, c), neq(a, c)],
        _ => [neq(a, b), neq(b, c), eq(a, c)],
    }
}

/// Single randomized sub-condition, used as a building block for self-cancelling duplicates.
fn condition<R: Rng>(rng: &mut R) -> VMCondition {
    match rng.gen_range(0..3) {
        0 => VMCondition {
            test: VMTest::CMP,
            lhs: pick(rng),
            rhs: rng.gen_range(0..=1),
        },
        1 => {
            let [a, b] = pick_two(rng);
            VMCondition {
                test: VMTest::EQ,
                lhs: a,
                rhs: b,
            }
        }
        _ => {
            let [a, b] = pick_two(rng);
            VMCondition {
                test: VMTest::NEQ,
                lhs: a,
                rhs: b,
            }
        }
    }
}

/// Randomly chosen [`VMFlag`] bit.
fn pick<R: Rng>(rng: &mut R) -> u8 {
    let flags = VMFlag::iter().collect::<Vec<VMFlag>>();
    *flags.choose(rng).unwrap() as u8
}

/// Two distinct randomly chosen [`VMFlag`] bits.
fn pick_two<R: Rng>(rng: &mut R) -> [u8; 2] {
    let mut flags = VMFlag::iter().collect::<Vec<VMFlag>>();
    flags.shuffle(rng);
    [flags[0] as u8, flags[1] as u8]
}

/// Three distinct randomly chosen [`VMFlag`] bits.
fn pick_three<R: Rng>(rng: &mut R) -> [u8; 3] {
    let mut flags = VMFlag::iter().collect::<Vec<VMFlag>>();
    flags.shuffle(rng);
    [flags[0] as u8, flags[1] as u8, flags[2] as u8]
}
