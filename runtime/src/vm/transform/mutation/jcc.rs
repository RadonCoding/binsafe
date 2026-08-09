use crate::vm::bytecode::{VMCondition, VMFlag, VMLogic, VMTest};
use crate::vm::encoders::jcc::{canonical, Jcc};
use crate::vm::encoders::Encode;
use crate::vm::transform::descend;
use rand::seq::SliceRandom;
use rand::Rng;
use strum::IntoEnumIterator;

/// Rewrites each [`Jcc`] in place via [`rewrite`].
pub fn walk<R: Rng>(operations: &mut Vec<Box<dyn Encode>>, rng: &mut R) {
    descend(operations, |operations| {
        for index in 0..operations.len() {
            let Some((logic, conditions)) = operations[index]
                .as_any()
                .downcast_ref::<Jcc>()
                .map(|jcc_ref| (jcc_ref.logic, jcc_ref.conditions.clone()))
            else {
                continue;
            };

            let polarity = conditions.iter().find_map(|condition| {
                if !canonical(condition) {
                    return None;
                }

                match condition.test {
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

            let (logic, conditions) = rewrite(rng, and, or, xor, logic, polarity, conditions);

            let jcc = operations[index]
                .as_any_mut()
                .downcast_mut::<Jcc>()
                .unwrap();

            jcc.logic = logic;
            jcc.conditions = conditions;
        }
    });
}

/// Rewrites each [`Jcc`] predicate structure and logic.
fn rewrite<R: Rng>(
    rng: &mut R,
    and: VMLogic,
    or: VMLogic,
    xor: VMLogic,
    logic: VMLogic,
    polarity: Option<bool>,
    conditions: Vec<VMCondition>,
) -> (VMLogic, Vec<VMCondition>) {
    let logic = match polarity {
        Some(truth) => {
            if truth {
                *[or, xor].choose(rng).unwrap()
            } else {
                *[and, xor].choose(rng).unwrap()
            }
        }
        None => {
            if conditions.len() == 1 {
                *[and, or, xor].choose(rng).unwrap()
            } else {
                logic
            }
        }
    };

    let mut conditions = build(rng, logic, polarity, conditions);

    conditions.shuffle(rng);
    dedup_conditions(&mut conditions);

    (logic, conditions)
}

/// Builds [`VMCondition`] entries under [`VMLogic`].
fn build<R: Rng>(
    rng: &mut R,
    logic: VMLogic,
    polarity: Option<bool>,
    mut conditions: Vec<VMCondition>,
) -> Vec<VMCondition> {
    let extra = rng.gen_range(1..=3);

    match polarity {
        Some(truth) => {
            let length = rng.gen_range(2..=4);
            let mut built = Vec::with_capacity(length);

            match (truth, is_and(logic), is_or(logic)) {
                (true, true, _) => {
                    while built.len() < length {
                        let candidate = always_true(rng, &built);

                        if !contains(&built, &candidate) {
                            built.push(candidate);
                        }
                    }
                }
                (true, _, true) => {
                    let count = rng.gen_range(1..=length.min(2));

                    for _ in 0..count {
                        let candidate = always_true(rng, &built);

                        if !contains(&built, &candidate) {
                            built.push(candidate);
                        }
                    }

                    while built.len() < length {
                        let candidate = condition(rng);

                        if !contains(&built, &candidate) {
                            built.push(candidate);
                        }
                    }
                }
                (true, false, false) => {
                    let odds = (1..=length)
                        .filter(|number| *number % 2 == 1)
                        .collect::<Vec<usize>>();
                    let count = *odds.choose(rng).unwrap();

                    for _ in 0..count {
                        let candidate = always_true(rng, &built);

                        if !contains(&built, &candidate) {
                            built.push(candidate);
                        }
                    }

                    while built.len() < length {
                        let candidate = always_false(rng, &built);

                        if !contains(&built, &candidate) {
                            built.push(candidate);
                        }
                    }
                }
                (false, true, _) => {
                    let count = rng.gen_range(1..=length.min(2));

                    for _ in 0..count {
                        let candidate = always_false(rng, &built);

                        if !contains(&built, &candidate) {
                            built.push(candidate);
                        }
                    }

                    while built.len() < length {
                        let candidate = condition(rng);

                        if !contains(&built, &candidate) {
                            built.push(candidate);
                        }
                    }
                }
                (false, _, true) => {
                    while built.len() < length {
                        let candidate = always_false(rng, &built);

                        if !contains(&built, &candidate) {
                            built.push(candidate);
                        }
                    }
                }
                (false, false, false) => {
                    let evens = (0..=length)
                        .filter(|number| *number % 2 == 0)
                        .collect::<Vec<usize>>();
                    let count = *evens.choose(rng).unwrap();

                    for _ in 0..count {
                        let candidate = always_true(rng, &built);

                        if !contains(&built, &candidate) {
                            built.push(candidate);
                        }
                    }

                    while built.len() < length {
                        let candidate = always_false(rng, &built);

                        if !contains(&built, &candidate) {
                            built.push(candidate);
                        }
                    }
                }
            }

            built
        }
        None => {
            if conditions.is_empty() {
                return conditions;
            }

            if is_and(logic) {
                for _ in 0..extra {
                    let candidate = always_true(rng, &conditions);

                    if !contains(&conditions, &candidate) {
                        conditions.push(candidate);
                    }
                }
            } else if is_or(logic) {
                for _ in 0..extra {
                    let candidate = always_false(rng, &conditions);

                    if !contains(&conditions, &candidate) {
                        conditions.push(candidate);
                    }
                }
            } else {
                if rng.gen_bool(0.5) {
                    for _ in 0..extra {
                        let candidate = always_false(rng, &conditions);

                        if !contains(&conditions, &candidate) {
                            conditions.push(candidate);
                        }
                    }
                } else {
                    let count = if rng.gen_bool(0.7) { 2 } else { 4 };

                    for _ in 0..count {
                        let candidate = always_true(rng, &conditions);

                        if !contains(&conditions, &candidate) {
                            conditions.push(candidate);
                        }
                    }
                }
            }

            conditions
        }
    }
}

/// Generates a proven TRUE [`VMCondition`] using identity tautologies.
fn always_true<R: Rng>(rng: &mut R, existing: &[VMCondition]) -> VMCondition {
    let mut candidates = Vec::new();

    for flag in VMFlag::iter() {
        candidates.push(VMCondition {
            test: VMTest::EQ,
            lhs: flag as u8,
            rhs: flag as u8,
        });
    }

    candidates.retain(|candidate| !contains(existing, candidate));

    if let Some(candidate) = candidates.choose(rng) {
        return candidate.clone();
    }

    let flag = pick(rng);

    VMCondition {
        test: VMTest::EQ,
        lhs: flag,
        rhs: flag,
    }
}

/// Generates a proven FALSE [`VMCondition`] using identity contradictions.
fn always_false<R: Rng>(rng: &mut R, existing: &[VMCondition]) -> VMCondition {
    let mut candidates = Vec::new();

    for flag in VMFlag::iter() {
        candidates.push(VMCondition {
            test: VMTest::NEQ,
            lhs: flag as u8,
            rhs: flag as u8,
        });
    }

    candidates.retain(|candidate| !contains(existing, candidate));

    if let Some(candidate) = candidates.choose(rng) {
        return candidate.clone();
    }

    let flag = pick(rng);

    VMCondition {
        test: VMTest::NEQ,
        lhs: flag,
        rhs: flag,
    }
}

/// Checks if the given [`VMLogic`] operator belongs to the AND family.
fn is_and(logic: VMLogic) -> bool {
    matches!(logic, VMLogic::JAND | VMLogic::CAND | VMLogic::SAND)
}

/// Checks if the given [`VMLogic`] operator belongs to the OR family.
fn is_or(logic: VMLogic) -> bool {
    matches!(logic, VMLogic::JOR | VMLogic::COR | VMLogic::SOR)
}

/// Deduplicates a vector of [`VMCondition`] entries in place.
fn dedup_conditions(conditions: &mut Vec<VMCondition>) {
    let mut unique = Vec::new();

    for condition in conditions.drain(..) {
        if !contains(&unique, &condition) {
            unique.push(condition);
        }
    }

    *conditions = unique;
}

/// Checks if a list of [`VMCondition`] entries already contains a specific condition.
fn contains(list: &[VMCondition], target: &VMCondition) -> bool {
    list.iter().any(|element| {
        element.test == target.test && element.lhs == target.lhs && element.rhs == target.rhs
    })
}

/// Random condition that mixes [`VMTest::CMP`], [`VMTest::EQ`], and [`VMTest::NEQ`] uniformly.
fn condition<R: Rng>(rng: &mut R) -> VMCondition {
    match rng.gen_range(0..3) {
        0 => VMCondition {
            test: VMTest::CMP,
            lhs: pick(rng),
            rhs: rng.gen_range(0..=1),
        },
        1 => {
            let [first, second] = pick_two(rng);

            VMCondition {
                test: VMTest::EQ,
                lhs: first,
                rhs: second,
            }
        }
        _ => {
            let [first, second] = pick_two(rng);

            VMCondition {
                test: VMTest::NEQ,
                lhs: first,
                rhs: second,
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
