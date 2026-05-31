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

struct Encryptor<'a> {
    operations: &'a mut Vec<Rc<dyn Encode>>,
    deadzones: Vec<bool>,
    position: usize,
    key: u64,
}

/// Encrypts every immediate against a rolling key held in [`VMReg::VImm`], emitting roll sequences between immediates.
pub fn encrypt(operations: Vec<Rc<dyn Encode>>) -> Vec<Rc<dyn Encode>> {
    let mut operations = operations;

    let key = rand::thread_rng().gen::<u64>();

    let mut encryptor = Encryptor::new(&mut operations, key);

    encryptor.process();
    encryptor.prologue(key);

    operations
}

impl<'a> Encryptor<'a> {
    /// Builds an [`Encryptor`] with a deadzone mask derived from a depth-first flag-effect scan over `operations` and their children.
    fn new(operations: &'a mut Vec<Rc<dyn Encode>>, key: u64) -> Self {
        let mut events = Vec::new();

        scan(operations, &mut events);

        let mut deadzones = vec![false; events.len()];
        let mut live = true;

        for (i, (reads, writes)) in events.iter().enumerate().rev() {
            if *reads {
                live = true;
            }
            if !live {
                deadzones[i] = true;
            }
            if *writes {
                live = false;
            }
        }

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

/// Recursively visits each leaf, recording whether it reads and whether it writes [`VMReg::Flags`].
fn scan(operations: &mut Vec<Rc<dyn Encode>>, events: &mut Vec<(bool, bool)>) {
    for op in operations.iter_mut() {
        if let Some(children) = Rc::get_mut(op).unwrap().children() {
            scan(children, events);

            continue;
        }

        let reads = op
            .reads()
            .iter()
            .any(|e| matches!(e, Effect::Register(VMReg::Flags)));

        let writes = op
            .writes()
            .iter()
            .any(|e| matches!(e, Effect::Register(VMReg::Flags)));

        events.push((reads, writes));
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

        if let Some(encrypted) = leaf(&operations[i], *key) {
            operations[i] = encrypted;

            let p = *position;
            *position += 1;

            if roll {
                let sequence = roll_sequence(key, !deadzones[p]);
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

/// Returns an encrypted replacement for a [`LoadImmediate`] or [`LoadAddress`] when one matches, otherwise [`None`].
fn leaf(operation: &Rc<dyn Encode>, key: u64) -> Option<Rc<dyn Encode>> {
    let any: &dyn Any = &**operation;

    if let Some(load) = any.downcast_ref::<LoadImmediate>() {
        let mut source = load.source.clone();

        xor(&mut source, load.width, key);

        return Some(Rc::new(LoadImmediate {
            width: load.width,
            source,
        }));
    }

    if let Some(load) = any.downcast_ref::<LoadAddress>() {
        let mut source = load.source;

        source.displacement ^= (key & 0xFFFF_FFFF) as i32;

        return Some(Rc::new(LoadAddress { source }));
    }

    None
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
fn roll_sequence(key: &mut u64, preserve: bool) -> Vec<Rc<dyn Encode>> {
    let mut rng = rand::thread_rng();
    let constant = rng.gen::<u64>();
    let cipher = constant ^ *key;

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
        width: VMWidth::Lower64,
        source: cipher.to_le_bytes().to_vec(),
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
