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

/// Rewrites each [`Jcc`] in place, dispatching always-true and always-false branches to [`opaque`], and runtime branches to [`mutated`].
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

            let (or, xor) = match logic {
                VMLogic::JAND | VMLogic::JOR | VMLogic::JXOR => (VMLogic::JOR, VMLogic::JXOR),
                VMLogic::CAND | VMLogic::COR | VMLogic::CXOR => (VMLogic::COR, VMLogic::CXOR),
                VMLogic::SAND | VMLogic::SOR | VMLogic::SXOR => (VMLogic::SOR, VMLogic::SXOR),
            };

            let (logic, conditions) = match polarity {
                Some(true) => opaque(rng, or, xor, true, &facts[i]),
                Some(false) => opaque(rng, or, xor, false, &facts[i]),
                None => (logic, mutated(rng, logic, conditions)),
            };

            let jcc = operations[i].as_any_mut().downcast_mut::<Jcc>().unwrap();
            jcc.logic = logic;
            jcc.conditions = conditions;
        }
    });
}

/// Expands each AND-family sub-condition through [`rewritten`] and appends a [`condition`] to XOR-family [`Jcc`]s, then shuffles.
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

/// Logically equivalent expansions of a sub-condition derived from flag invariants.
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
    facts: &[(VMFlag, bool)],
) -> (VMLogic, Vec<VMCondition>) {
    let base = match fact(rng, facts, polarity).filter(|_| !facts.is_empty()) {
        Some(condition) => vec![condition],
        None if polarity => tautology(rng),
        None => vec![antitautology(rng)],
    };

    let logic = if rng.gen() { or } else { xor };
    let mut conditions = base;
    conditions.shuffle(rng);

    (logic, conditions)
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

/// A flag bit compared for inequality against itself.
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

/// Two sub-conditions comparing the same flag bit against both possible values, of which one is thruthful.
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

/// Two sub-conditions testing equality and inequality of two distinct flag bits, of which one is thruthful.
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

/// Three pairwise sub-conditions over three distinct flag bits, of which an odd number are truthful.
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

/// Three distinct randomly chosen [`VMFlag`] bits.
fn pick_three<R: Rng>(rng: &mut R) -> [u8; 3] {
    let mut flags = VMFlag::iter().collect::<Vec<VMFlag>>();
    flags.shuffle(rng);
    [flags[0] as u8, flags[1] as u8, flags[2] as u8]
}
