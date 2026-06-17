use std::any::Any;
use std::rc::Rc;

use rand::seq::SliceRandom;
use rand::Rng;
use strum::IntoEnumIterator;

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMCondition, VMFlag, VMLogic, VMTest};
use crate::vm::encoders::jcc::{is_canonical, Jcc};
use crate::vm::encoders::Encode;
use crate::vm::transform::{descend, downcast, Phase, Transform};

pub struct Mutation;

impl Transform for Mutation {
    fn phase(&self) -> Phase {
        Phase::Mutation
    }

    fn run(&self, _mapper: &mut Mapper, operations: Vec<Rc<dyn Encode>>) -> Vec<Rc<dyn Encode>> {
        let mut operations = operations;
        let mut rng = rand::thread_rng();
        walk(&mut operations, &mut rng);
        operations
    }
}

/// Rewrites each [`Jcc`] in place, dispatching always-true and always-false branches to [`opaque`], and runtime branches to [`mutated`].
fn walk<R: Rng>(operations: &mut Vec<Rc<dyn Encode>>, rng: &mut R) {
    descend(operations, |operations| {
        for i in 0..operations.len() {
            let Some((logic, conditions)) =
                downcast::<Jcc>(&operations[i]).map(|j| (j.logic, j.conditions.clone()))
            else {
                continue;
            };

            let polarity = conditions.iter().find_map(|c| {
                if !is_canonical(c) {
                    return None;
                }
                match c.test {
                    VMTest::EQ => Some(true),
                    VMTest::NEQ => Some(false),
                    _ => None,
                }
            });

            let (or, xor) = match logic {
                VMLogic::JAND | VMLogic::JOR | VMLogic::JXOR => (VMLogic::JOR, VMLogic::JXOR),
                VMLogic::CAND | VMLogic::COR | VMLogic::CXOR => (VMLogic::COR, VMLogic::CXOR),
                VMLogic::SAND | VMLogic::SOR | VMLogic::SXOR => (VMLogic::SOR, VMLogic::SXOR),
            };

            let (logic, conditions) = match polarity {
                Some(true) => opaque(rng, or, xor, true),
                Some(false) => opaque(rng, or, xor, false),
                None => (logic, mutated(rng, logic, conditions)),
            };

            let any: &mut dyn Any = Rc::get_mut(&mut operations[i]).unwrap();
            let jcc = any.downcast_mut::<Jcc>().unwrap();
            jcc.logic = logic;
            jcc.conditions = conditions;
        }
    });
}

/// Expands each AND-family sub-condition through [`rewritten`] and appends a [`neutral_pair`] to XOR-family [`Jcc`]s, then shuffles.
fn mutated<R: Rng>(
    rng: &mut R,
    logic: VMLogic,
    mut conditions: Vec<VMCondition>,
) -> Vec<VMCondition> {
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
            if rng.gen() {
                let condition = condition(rng);
                conditions.push(condition);
                conditions.push(condition);
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

/// Builds an always-true or always-false predicate by picking between the OR and XOR families.
fn opaque<R: Rng>(
    rng: &mut R,
    or: VMLogic,
    xor: VMLogic,
    polarity: bool,
) -> (VMLogic, Vec<VMCondition>) {
    if rng.gen() {
        let mut conditions = if polarity {
            tautology(rng)
        } else {
            vec![antitautology(rng)]
        };
        conditions.shuffle(rng);
        (or, conditions)
    } else {
        let mut conditions = tautology(rng);

        if polarity {
            if rng.gen() {
                let c = condition(rng);
                conditions.push(c.clone());
                conditions.push(c);
            }
        } else {
            let condition = condition(rng);
            conditions = vec![condition, condition];
        }
        conditions.shuffle(rng);
        (xor, conditions)
    }
}

/// A flag bit compared for inequality against itself, always evaluates false at runtime.
fn antitautology<R: Rng>(rng: &mut R) -> VMCondition {
    let flag = pick(rng);
    VMCondition {
        test: VMTest::NEQ,
        lhs: flag,
        rhs: flag,
    }
}

/// One or two sub-conditions that always include an odd number of true results.
fn tautology<R: Rng>(rng: &mut R) -> Vec<VMCondition> {
    match rng.gen_range(0..3) {
        0 => cmp_pair(rng).to_vec(),
        1 => eq_pair(rng).to_vec(),
        _ => triple_eq(rng).to_vec(),
    }
}

/// Two sub-conditions comparing the same flag bit against both possible values, exactly one of which is true at runtime.
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

/// Two sub-conditions testing equality and inequality of two distinct flag bits, exactly one of which is true at runtime.
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

/// Three pairwise sub-conditions over three distinct flag bits, always with an odd number true at runtime.
fn triple_eq<R: Rng>(rng: &mut R) -> [VMCondition; 3] {
    let [a, b, c] = pick_three(rng);
    let eq = |l, r| VMCondition {
        test: VMTest::EQ,
        lhs: l,
        rhs: r,
    };
    let neq = |l, r| VMCondition {
        test: VMTest::NEQ,
        lhs: l,
        rhs: r,
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
    let flags = VMFlag::iter().collect::<Vec<_>>();
    *flags.choose(rng).unwrap() as u8
}

/// Two distinct randomly chosen [`VMFlag`] bits.
fn pick_two<R: Rng>(rng: &mut R) -> [u8; 2] {
    let mut flags = VMFlag::iter().collect::<Vec<_>>();
    flags.shuffle(rng);
    [flags[0] as u8, flags[1] as u8]
}

/// Three distinct randomly chosen [`VMFlag`] bits.
fn pick_three<R: Rng>(rng: &mut R) -> [u8; 3] {
    let mut flags = VMFlag::iter().collect::<Vec<_>>();
    flags.shuffle(rng);
    [flags[0] as u8, flags[1] as u8, flags[2] as u8]
}
