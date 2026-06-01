use std::any::Any;
use std::rc::Rc;

use rand::Rng;

use crate::vm::bytecode::{VMReg, VMWidth};
use crate::vm::encoders::add::Add;
use crate::vm::encoders::load_address::LoadAddress;
use crate::vm::encoders::load_immediate::LoadImmediate;
use crate::vm::encoders::load_register::LoadRegister;
use crate::vm::encoders::store_register::StoreRegister;
use crate::vm::encoders::sub::Sub;
use crate::vm::encoders::xor::Xor;
use crate::vm::encoders::{Effect, Encode};
use crate::vm::transform::{deadzones, Phase, Transform};

struct Encryptor<'a> {
    operations: &'a mut Vec<Rc<dyn Encode>>,
    deadzones: Vec<bool>,
    position: usize,
    key: u64,
}

/// Encrypts every immediate against a rolling key held in [`VMReg::VImm`], emitting roll sequences between immediates.
pub struct Encrypt;

impl Transform for Encrypt {
    fn phase(&self) -> Phase {
        Phase::Encrypt
    }

    fn run(&self, operations: Vec<Rc<dyn Encode>>) -> Vec<Rc<dyn Encode>> {
        let mut operations = operations;

        let key = rand::thread_rng().gen::<u64>();

        let mut encryptor = Encryptor::new(&mut operations, key);

        encryptor.process();
        encryptor.prologue(key);

        operations
    }
}

impl<'a> Encryptor<'a> {
    /// Builds an [`Encryptor`] with a deadzone mask derived from a depth-first flag-effect scan over `operations` and their children.
    fn new(operations: &'a mut Vec<Rc<dyn Encode>>, key: u64) -> Self {
        let deadzones = deadzones(operations, |effect| {
            matches!(effect, Effect::Register(VMReg::Flags))
        });

        Self {
            operations,
            deadzones,
            position: 0,
            key,
        }
    }

    /// Encrypts each operation in execution order, rolling the key after every immediate.
    fn process(&mut self) {
        walk(
            self.operations,
            &mut self.position,
            &self.deadzones,
            &mut self.key,
            true,
        );
    }

    /// Emits the seed sequence that initializes [`VMReg::VImm`] to the starting key.
    fn prologue(&mut self, key: u64) {
        self.operations.insert(
            0,
            Rc::new(LoadImmediate {
                width: VMWidth::Lower64,
                source: key.to_le_bytes().to_vec(),
            }),
        );
        self.operations.insert(
            1,
            Rc::new(StoreRegister {
                width: VMWidth::Lower64,
                destination: VMReg::VImm,
            }),
        );
    }
}

/// Encrypts each leaf in place, descending into children with `roll` cleared and splicing a roll sequence after every immediate when `roll` is set.
fn walk(
    operations: &mut Vec<Rc<dyn Encode>>,
    position: &mut usize,
    deadzones: &[bool],
    key: &mut u64,
    roll: bool,
) {
    let mut i = 0;

    while i < operations.len() {
        if let Some(children) = Rc::get_mut(&mut operations[i]).unwrap().children() {
            walk(children, position, deadzones, key, false);

            i += 1;
            continue;
        }

        if leaf(&mut operations[i], *key) {
            let p = *position;
            *position += 1;

            if roll {
                let sequence = rolling(key, !deadzones[p]);
                let length = sequence.len();
                operations.splice(i + 1..i + 1, sequence);
                i += length;
            }
        } else {
            *position += 1;
        }

        i += 1;
    }
}

/// Encrypts the leaf in place when it matches [`LoadImmediate`] or [`LoadAddress`], returning whether a match was found.
fn leaf(operation: &mut Rc<dyn Encode>, key: u64) -> bool {
    let any: &mut dyn Any = Rc::get_mut(operation).unwrap();

    if let Some(load) = any.downcast_mut::<LoadImmediate>() {
        xor(&mut load.source, load.width, key);

        return true;
    }

    if let Some(load) = any.downcast_mut::<LoadAddress>() {
        load.source.displacement ^= (key & 0xFFFF_FFFF) as i32;

        return true;
    }

    false
}

/// XORs `source` byte-for-byte against the width-matching slice of `key`.
fn xor(source: &mut [u8], width: VMWidth, key: u64) {
    let bytes = key.to_le_bytes();
    let offset = if width == VMWidth::Higher8 { 1 } else { 0 };

    for (i, byte) in source.iter_mut().enumerate() {
        *byte ^= bytes[offset + i];
    }
}

/// Builds a random arithmetic equence and updates `key` to match, bracketing with a [`VMReg::Flags`] save/restore when the flags are live.
fn rolling(key: &mut u64, preserve: bool) -> Vec<Rc<dyn Encode>> {
    let mut rng = rand::thread_rng();

    let (width, bytes) = match rng.gen_range(0..16) {
        0..=9 => (VMWidth::Lower8, 1),
        10..=13 => (VMWidth::Lower16, 2),
        14 => (VMWidth::Lower32, 4),
        _ => (VMWidth::Lower64, 8),
    };

    let mask = if bytes == 8 {
        !0u64
    } else {
        (1u64 << (bytes * 8)) - 1
    };

    let constant = rng.gen::<u64>() & mask;

    let cipher = (constant ^ *key) & mask;

    let mut sequence = Vec::new();

    if preserve {
        sequence.push(Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: VMReg::Flags,
        }) as Rc<dyn Encode>);
    }

    sequence.push(Rc::new(LoadRegister {
        width: VMWidth::Lower64,
        source: VMReg::VImm,
    }) as Rc<dyn Encode>);

    sequence.push(Rc::new(LoadImmediate {
        width,
        source: cipher.to_le_bytes()[..bytes].to_vec(),
    }));

    match rng.gen_range(0..3) {
        0 => {
            sequence.push(Rc::new(Xor {
                width: VMWidth::Lower64,
            }));
            *key ^= constant;
        }
        1 => {
            sequence.push(Rc::new(Add {
                width: VMWidth::Lower64,
            }));
            *key = key.wrapping_add(constant);
        }
        _ => {
            sequence.push(Rc::new(Sub {
                width: VMWidth::Lower64,
            }));
            *key = key.wrapping_sub(constant);
        }
    }

    sequence.push(Rc::new(StoreRegister {
        width: VMWidth::Lower64,
        destination: VMReg::VImm,
    }));

    if preserve {
        sequence.push(Rc::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: VMReg::Flags,
        }));
    }

    sequence
}
