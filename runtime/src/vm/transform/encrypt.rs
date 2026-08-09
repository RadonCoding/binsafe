use std::collections::HashSet;
use std::matches;
use std::sync::Mutex;

use rand::Rng;

use crate::mapper::Mapper;
use crate::vm::bytecode::{VMReg, VMWidth};
use crate::vm::encoders::chain::Chain;
use crate::vm::encoders::discard::Discard;
use crate::vm::encoders::load_address::LoadAddress;
use crate::vm::encoders::load_immediate::LoadImmediate;
use crate::vm::encoders::load_register::LoadRegister;
use crate::vm::encoders::mul::Mul;
use crate::vm::encoders::rol::Rol;
use crate::vm::encoders::ror::Ror;
use crate::vm::encoders::skip::Skip;
use crate::vm::encoders::store_register::StoreRegister;
use crate::vm::encoders::xor::Xor;
use crate::vm::encoders::{identity, Effect, Encode};
use crate::vm::snapshot::Snapshots;
use crate::vm::transform::{deadzones, Phase, Transform};

struct Encryptor<'a> {
    mapper: &'a mut Mapper,
    operations: &'a mut Vec<Box<dyn Encode>>,
    addend: u64,
    multiplier: u64,
}

/// Encrypts every immediate against rolling immediates held in [`VMReg::VImmAdd`] and [`VMReg::VImmMul`].
pub struct Encrypt;

impl Transform for Encrypt {
    fn phase(&self) -> Phase {
        Phase::Encrypt
    }

    fn run(&self, mapper: &mut Mapper, operations: Vec<Box<dyn Encode>>) -> Vec<Box<dyn Encode>> {
        let mut operations = operations;

        let addend = rand::thread_rng().gen::<u64>();
        let multiplier = rand::thread_rng().gen::<u64>() | 1;

        let mut encryptor = Encryptor::new(mapper, &mut operations, addend, multiplier);

        encryptor.process();
        encryptor.prologue(addend, multiplier);

        operations
    }
}

impl<'a> Encryptor<'a> {
    /// Builds an [`Encryptor`] with a deadzone mask derived from a depth-first flag-effect scan over `operations` and their children.
    fn new(
        mapper: &'a mut Mapper,
        operations: &'a mut Vec<Box<dyn Encode>>,
        addend: u64,
        multiplier: u64,
    ) -> Self {
        Self {
            mapper,
            operations,
            addend,
            multiplier,
        }
    }

    /// Encrypts each operation in execution order, rolling both keys after every immediate.
    fn process(&mut self) {
        let mut snapshots = Snapshots::new();
        snapshots.record(Phase::Lift, self.operations);
        walk(
            self.mapper,
            self.operations,
            &mut self.addend,
<<<<<<< HEAD
            &mut self.multiplier,
            &snapshots,
            0,
=======
            &mut self.multiplier
>>>>>>> b76e14330923c430b672659e7443bb1dfa759464
        );
    }

    /// Emits the seed sequence for [`VMReg::VImmAdd`] and [`VMReg::VImmMul`].
    fn prologue(&mut self, addend: u64, multiplier: u64) {
        self.operations.insert(
            0,
            Box::new(LoadImmediate {
                width: VMWidth::Lower64,
                source: addend.to_le_bytes().to_vec(),
            }),
        );
        self.operations.insert(
            1,
            Box::new(LoadImmediate {
                width: VMWidth::Lower64,
                source: invert(multiplier).to_le_bytes().to_vec(),
            }),
        );
        self.operations.insert(
            2,
            Box::new(StoreRegister {
                width: VMWidth::Lower64,
                destination: VMReg::VImmMul,
            }),
        );
        self.operations.insert(
            3,
            Box::new(StoreRegister {
                width: VMWidth::Lower64,
                destination: VMReg::VImmAdd,
            }),
        );
    }
}

/// Emits a sequence to restore [`VMReg::VImmAdd`]/[`VMReg::VImmMul`] using the current values.
fn restore(
    destination_addend: u64,
    destination_multiplier: u64,
    source_addend: u64,
    source_multiplier: u64,
) -> Vec<Box<dyn Encode>> {
    let mut sequence = Vec::<Box<dyn Encode>>::new();

    let mut source = destination_addend.to_le_bytes().to_vec();
    encrypt(&mut source, source_addend, source_multiplier);
    sequence.push(Box::new(LoadImmediate {
        width: VMWidth::Lower64,
        source,
    }));

    let mut source = invert(destination_multiplier).to_le_bytes().to_vec();
    encrypt(&mut source, source_addend, source_multiplier);
    sequence.push(Box::new(LoadImmediate {
        width: VMWidth::Lower64,
        source,
    }));

    sequence.push(Box::new(StoreRegister {
        width: VMWidth::Lower64,
        destination: VMReg::VImmMul,
    }));

    sequence.push(Box::new(StoreRegister {
        width: VMWidth::Lower64,
        destination: VMReg::VImmAdd,
    }));

    sequence
}

static PRINTED: Mutex<Option<HashSet<usize>>> = Mutex::new(None);

/// Encrypts each leaf in place splicing a roll sequence after every top-level immediate.
fn walk(
    mapper: &mut Mapper,
    operations: &mut Vec<Box<dyn Encode>>,
    addend: &mut u64,
    multiplier: &mut u64,
<<<<<<< HEAD
    snapshots: &Snapshots,
    level: i32,
=======
>>>>>>> b76e14330923c430b672659e7443bb1dfa759464
) -> Vec<(u64, u64)> {
    let outer_addend = *addend;
    let outer_multiplier = *multiplier;

    let deadzones = deadzones(operations, |effect| {
        matches!(effect, Effect::Register(VMReg::Flags))
    });

    let mut trace = Vec::with_capacity(operations.len());

    let mut i = 0;

    let mut position = 0;

    while i < operations.len() {
        trace.push((*addend, *multiplier));

        if let Some(children) = operations[i].children_mut() {
            let mut inner_addend = *addend;
            let mut inner_multiplier = *multiplier;

            let mut inner_trace = walk(
                mapper,
                children,
                &mut inner_addend,
<<<<<<< HEAD
                &mut inner_multiplier,
                snapshots,
                level + 1,
=======
                &mut inner_multiplier
>>>>>>> b76e14330923c430b672659e7443bb1dfa759464
            );

            if inner_addend != *addend || inner_multiplier != *multiplier {
                let sequence = restore(*addend, *multiplier, inner_addend, inner_multiplier);
                let length = sequence.len();
                children.extend(sequence);

                for _ in 0..length {
                    inner_trace.push((*addend, *multiplier));
                }
            }

            operations[i].seal(mapper, &mut |source: &mut [u8], index| {
                let (addend, multiplier) = inner_trace[index];
                encrypt(source, addend, multiplier);
            });

            i += 1;

            position += 1;

            continue;
        }

<<<<<<< HEAD
        if operations[i].is_destination() {
            let sequence = restore(outer_addend, outer_multiplier, *addend, *multiplier);
            let length = sequence.len();
            operations.splice(i..i, sequence);

            *addend = outer_addend;
            *multiplier = outer_multiplier;

            for j in 0..length {
                trace.insert(i + j, (*addend, *multiplier));
            }

            i += length + 1;

            position += 1;

            continue;
        }

        if operations[i].is_branch() {
            let sequence = restore(outer_addend, outer_multiplier, *addend, *multiplier);
            let length = sequence.len();
            operations.splice(i..i, sequence);

            *addend = outer_addend;
            *multiplier = outer_multiplier;

            for j in 0..length {
                trace.insert(i + j, (*addend, *multiplier));
            }

            i += length + 1;

            position += 1;

            continue;
        }

        if leaf(&mut operations[i], *addend, *multiplier) {
            let sequence = transform(addend, multiplier, !deadzones[position]);
            let length = sequence.len();
            operations.splice(i + 1..i + 1, sequence);

            for _ in 0..length {
                trace.push((*addend, *multiplier));
            }

=======
        if leaf(&mut operations[i], *addend, *multiplier) {
            let sequence = transform(addend, multiplier, !deadzones[position]);
            let length = sequence.len();
            operations.splice(i + 1..i + 1, sequence);

            for _ in 0..length {
                trace.push((*addend, *multiplier));
            }

>>>>>>> b76e14330923c430b672659e7443bb1dfa759464
            i += length;
        }

        i += 1;
<<<<<<< HEAD

=======
        
>>>>>>> b76e14330923c430b672659e7443bb1dfa759464
        position += 1;
    }

    trace
}

/// Encrypts the leaf in place when it matches [`LoadImmediate`] or [`LoadAddress`], returning whether a match was found.
fn leaf(operation: &mut Box<dyn Encode>, addend: u64, multiplier: u64) -> bool {
    if let Some(load) = operation.as_any_mut().downcast_mut::<LoadImmediate>() {
        encrypt(&mut load.source, addend, multiplier);
        return true;
    }

    if let Some(load) = operation.as_any_mut().downcast_mut::<LoadAddress>() {
        let mut displacement = load.source.displacement.to_le_bytes();
        encrypt(&mut displacement, addend, multiplier);
        load.source.displacement = i32::from_le_bytes(displacement);
        return true;
    }

    false
}

/// Computes the multiplicative inverse of odd `x` modulo 2^64.
fn invert(x: u64) -> u64 {
    let mut inverse = x;

    for _ in 0..5 {
        inverse = inverse.wrapping_mul(2u64.wrapping_sub(x.wrapping_mul(inverse)));
    }

    inverse
}

/// Encrypts `source` against `addend` and `multiplier`.
fn encrypt(source: &mut [u8], addend: u64, multiplier: u64) {
    let mut buffer = [0u8; 8];
    buffer[..source.len()].copy_from_slice(source);

    let plaintext = u64::from_le_bytes(buffer);
    let ciphertext = plaintext.wrapping_add(addend).wrapping_mul(multiplier);
    source.copy_from_slice(&ciphertext.to_le_bytes()[..source.len()]);
}

/// Creates a random transformation sequence for [`VMReg::VImmAdd`] and [`VMReg::VImmMul`] while preserving flags.
fn transform(addend: &mut u64, multiplier: &mut u64, preserve: bool) -> Vec<Box<dyn Encode>> {
    let mut rng = rand::thread_rng();

    let mut sequence = Vec::<Box<dyn Encode>>::new();

    if preserve {
        sequence.push(Box::new(LoadRegister {
            width: VMWidth::Lower64,
            source: VMReg::Flags,
        }));
    }

    match rng.gen_range(0..2) {
        0 => {
            let (width, mut source, operation, apply): (
                VMWidth,
                Vec<u8>,
                Box<dyn Encode>,
                Box<dyn FnOnce(&mut u64)>,
            ) = match rng.gen_range(0..3) {
                0 => {
                    let (width, constant) = match rng.gen_range(0..10) {
                        0..=4 => (VMWidth::Lower8, rng.gen::<u8>() as u64),
                        5..=7 => (VMWidth::Lower16, rng.gen::<u16>() as u64),
                        8 => (VMWidth::Lower32, rng.gen::<u32>() as u64),
                        _ => (VMWidth::Lower64, rng.gen::<u64>()),
                    };

                    (
                        width,
                        constant.to_le_bytes()[..width.size()].to_vec(),
                        Box::new(Xor {
                            width: VMWidth::Lower64,
                        }),
                        Box::new(move |addend| *addend ^= constant),
                    )
                }
                1 => {
                    let count = rng.gen_range(1..64u32);

                    (
                        VMWidth::Lower8,
                        vec![count as u8],
                        Box::new(Rol {
                            width: VMWidth::Lower64,
                        }),
                        Box::new(move |addend| *addend = addend.rotate_left(count)),
                    )
                }
                _ => {
                    let count = rng.gen_range(1..64u32);

                    (
                        VMWidth::Lower8,
                        vec![count as u8],
                        Box::new(Ror {
                            width: VMWidth::Lower64,
                        }),
                        Box::new(move |addend| *addend = addend.rotate_right(count)),
                    )
                }
            };

            encrypt(&mut source, *addend, *multiplier);

            sequence.push(Box::new(LoadRegister {
                width: VMWidth::Lower64,
                source: VMReg::VImmAdd,
            }));

            sequence.push(Box::new(LoadImmediate { width, source }));

            sequence.push(operation);

            sequence.push(Box::new(StoreRegister {
                width: VMWidth::Lower64,
                destination: VMReg::VImmAdd,
            }));

            apply(addend);
        }
        _ => {
            let (width, factor, mut source): (VMWidth, u64, Vec<u8>) = match rng.gen_range(0..10) {
                0..=4 => {
                    let v = rng.gen::<u8>() | 1;
                    (VMWidth::Lower8, v as u64, v.to_le_bytes().to_vec())
                }
                5..=7 => {
                    let v = rng.gen::<u16>() | 1;
                    (VMWidth::Lower16, v as u64, v.to_le_bytes().to_vec())
                }
                8 => {
                    let v = rng.gen::<u32>() | 1;
                    (VMWidth::Lower32, v as u64, v.to_le_bytes().to_vec())
                }
                _ => {
                    let v = rng.gen::<u64>() | 1;
                    (VMWidth::Lower64, v, v.to_le_bytes().to_vec())
                }
            };

            let inverse = invert(factor);

            encrypt(&mut source, *addend, *multiplier);

            sequence.push(Box::new(LoadRegister {
                width: VMWidth::Lower64,
                source: VMReg::VImmMul,
            }));

            sequence.push(Box::new(LoadImmediate { width, source }));
            sequence.push(Box::new(Mul {
                width: VMWidth::Lower64,
            }));

            sequence.push(Box::new(StoreRegister {
                width: VMWidth::Lower64,
                destination: VMReg::VImmMul,
            }));

            sequence.push(Box::new(Discard::new()));

            *multiplier = multiplier.wrapping_mul(inverse);
        }
    }

    if preserve {
        sequence.push(Box::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: VMReg::Flags,
        }));
    }

    sequence
}
