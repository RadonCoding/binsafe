use rand::seq::SliceRandom;
use rand::Rng;
use strum::IntoEnumIterator;

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMCondition, VMFlag, VMLogic, VMReg, VMTest};
use crate::vm::encoders::jcc::{canonical, Jcc};
use crate::vm::encoders::sub::Sub;
use crate::vm::encoders::xor::Xor;
use crate::vm::encoders::{Effect, Encode};
use crate::vm::transform::{descend, Phase, Transform};

pub struct Mutation;

impl Transform for Mutation {
    fn phase(&self) -> Phase {
        Phase::Mutation
    }

    fn run(&self, _mapper: &mut Mapper, operations: Vec<Box<dyn Encode>>) -> Vec<Box<dyn Encode>> {
        let mut operations = operations;
        let mut rng = rand::thread_rng();
        walk(&mut operations, &mut rng);
        operations
    }
}

/// Per-leaf flags mask computed via a forward walk over the leaves.
fn facts(operations: &[Box<dyn Encode>]) -> Vec<Vec<(VMFlag, bool)>> {
    let mut established = vec![None; operations.len()];
    let mut live = vec![Vec::new(); operations.len()];
    let mut current = Vec::new();

    for (i, operation) in operations.iter().enumerate() {
        let cancelling = operation.as_any().downcast_ref::<Xor>().is_some()
            || operation.as_any().downcast_ref::<Sub>().is_some();

        if cancelling && duplicated(&operations[..i]).is_some() {
            established[i] = Some(vec![
                (VMFlag::Zero, true),
                (VMFlag::Sign, false),
                (VMFlag::Parity, true),
                (VMFlag::Carry, false),
                (VMFlag::Overflow, false),
            ]);
        }

        let writes = operation
            .writes()
            .iter()
            .any(|effect| matches!(effect, Effect::Register(VMReg::Flags)));
        if writes || operation.is_target() || operation.is_branch() {
            current.clear();
        }

        live[i] = current.clone();

        if let Some(facts) = &established[i] {
            current = facts.clone();
        }
    }
    live
}

/// Whether the last two reads before an instruction both point to the same register.
fn duplicated(prefix: &[Box<dyn Encode>]) -> Option<VMReg> {
    let reads = |instruction: &Box<dyn Encode>| -> Vec<VMReg> {
        instruction
            .reads()
            .iter()
            .filter_map(|effect| match effect {
                Effect::Register(register) => Some(*register),
                _ => None,
            })
            .collect()
    };

    let second = prefix.last()?;
    let first = prefix.get(prefix.len().checked_sub(2)?)?;

    let a = reads(first);
    let b = reads(second);

    a.iter()
        .find_map(|register| b.contains(register).then_some(*register))
}

/// Rewrites each [`Jcc`] in place via [`rewrite`].
fn walk<R: Rng>(operations: &mut Vec<Box<dyn Encode>>, rng: &mut R) {
    descend(operations, |operations| {
        let facts = facts(operations);
        for i in 0..operations.len() {
            let Some((logic, conditions)) = operations[i]
                .as_any()
                .downcast_ref::<Jcc>()
                .map(|j| (j.logic, j.conditions.clone()))
            else {
                continue;
            };

            let polarity = conditions.iter().find_map(|c| {
                if !canonical(c) {
                    return None;
                }
                match c.test {
                    VMTest::EQ => Some(true),
                    VMTest::NEQ => Some(false),
                    _ => None,
                }
            });

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

            let (logic, conditions) =
                rewrite(rng, and, or, xor, logic, polarity, conditions, &facts[i]);

            let jcc = operations[i].as_any_mut().downcast_mut::<Jcc>().unwrap();
            jcc.logic = logic;
            jcc.conditions = conditions;
        }
    });
}

/// Dispatches each [`Jcc`] to opaque or runtime-dependent rewriting, rerolling logic for single-condition branches, and pads to at least two conditions.
fn rewrite<R: Rng>(
    rng: &mut R,
    and: VMLogic,
    or: VMLogic,
    xor: VMLogic,
    logic: VMLogic,
    polarity: Option<bool>,
    conditions: Vec<VMCondition>,
    facts: &[(VMFlag, bool)],
) -> (VMLogic, Vec<VMCondition>) {
    let (logic, mut conditions) = match polarity {
        Some(truth) => {
            let logic = if !facts.is_empty() {
                *[and, or, xor].choose(rng).unwrap()
            } else if truth {
                *[or, xor].choose(rng).unwrap()
            } else {
                xor
            };
            let mut conditions = if truth {
                thruthful(rng, facts)
            } else {
                falseful(rng, facts)
            };
            pad(rng, logic, truth, &mut conditions, true, facts);
            (logic, conditions)
        }
        None => {
            let logic = if conditions.len() == 1 {
                *[and, or, xor].choose(rng).unwrap()
            } else {
                logic
            };
            let mut conditions = expand(rng, logic, conditions);
            pad(rng, logic, false, &mut conditions, false, facts);
            (logic, conditions)
        }
    };
    conditions.shuffle(rng);
    (logic, conditions)
}

/// Expands AND-family conditions through [`rewrite`] and duplicates a fresh condition for XOR-family logic.
fn expand<R: Rng>(
    rng: &mut R,
    logic: VMLogic,
    mut conditions: Vec<VMCondition>,
) -> Vec<VMCondition> {
    match logic {
        VMLogic::JXOR | VMLogic::CXOR | VMLogic::SXOR => {
            let condition = condition(rng);
            conditions.push(condition.clone());
            conditions.push(condition);
        }
        _ => {}
    }
    conditions
}

/// Appends truth-preserving conditions until at least two conditions are present.
fn pad<R: Rng>(
    rng: &mut R,
    logic: VMLogic,
    truth: bool,
    conditions: &mut Vec<VMCondition>,
    known: bool,
    facts: &[(VMFlag, bool)],
) {
    while conditions.len() < 2 {
        match logic {
            VMLogic::JAND | VMLogic::CAND | VMLogic::SAND => {
                let c = if known && !truth {
                    None
                } else {
                    fact(rng, facts, true).or_else(|| conditions.choose(rng).cloned())
                };
                match c {
                    Some(c) => conditions.push(c),
                    None => break,
                }
            }
            VMLogic::JOR | VMLogic::COR | VMLogic::SOR => {
                let c = if known && truth {
                    Some(condition(rng))
                } else {
                    fact(rng, facts, false).or_else(|| conditions.choose(rng).cloned())
                };
                match c {
                    Some(c) => conditions.push(c),
                    None => break,
                }
            }
            VMLogic::JXOR | VMLogic::CXOR | VMLogic::SXOR => {
                let c = condition(rng);
                conditions.push(c.clone());
                conditions.push(c);
            }
        }
    }
}

/// Generates a proven true condition.
fn thruthful<R: Rng>(rng: &mut R, facts: &[(VMFlag, bool)]) -> Vec<VMCondition> {
    if let Some(c) = fact(rng, facts, true) {
        return vec![c];
    }
    let c = condition(rng);
    vec![c.clone(), negate(&c)]
}

/// Generates a proven false condition.
fn falseful<R: Rng>(rng: &mut R, facts: &[(VMFlag, bool)]) -> Vec<VMCondition> {
    if let Some(c) = fact(rng, facts, false) {
        return vec![c];
    }
    let c = condition(rng);
    vec![c.clone(), c]
}

/// [`VMCondition`] against a flag proven true or false by a preceding self-cancelling instruction.
fn fact<R: Rng>(rng: &mut R, facts: &[(VMFlag, bool)], polarity: bool) -> Option<VMCondition> {
    let &(flag, value) = facts.choose(rng)?;
    let value = if polarity { value } else { !value };
    Some(VMCondition {
        test: VMTest::CMP,
        lhs: flag as u8,
        rhs: value as u8,
    })
}

/// Single randomized sub-condition.
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

/// Complementary [`VMCondition`] with inverted sense.
fn negate(c: &VMCondition) -> VMCondition {
    match c.test {
        VMTest::CMP => VMCondition {
            test: VMTest::CMP,
            lhs: c.lhs,
            rhs: 1 - c.rhs,
        },
        VMTest::EQ => VMCondition {
            test: VMTest::NEQ,
            lhs: c.lhs,
            rhs: c.rhs,
        },
        VMTest::NEQ => VMCondition {
            test: VMTest::EQ,
            lhs: c.lhs,
            rhs: c.rhs,
        },
    }
}
