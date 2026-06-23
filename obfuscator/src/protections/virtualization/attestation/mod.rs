use std::i32;
use std::rc::Rc;

use crate::engine::Engine;
use rand::Rng;
use runtime::runtime::{FnDef, ImportDef};
use runtime::vm::bytecode::{VMCondition, VMFlag, VMLogic, VMMem, VMReg, VMSeg, VMWidth};
use runtime::vm::encoders::add::Add;
use runtime::vm::encoders::and::And;
use runtime::vm::encoders::chain::{Chain, Jump, Target};
use runtime::vm::encoders::discard::Discard;
use runtime::vm::encoders::jcc::Jcc;
use runtime::vm::encoders::load_address::LoadAddress;
use runtime::vm::encoders::load_immediate::LoadImmediate;
use runtime::vm::encoders::load_memory::LoadMemory;
use runtime::vm::encoders::load_register::LoadRegister;
use runtime::vm::encoders::skip::Skip;
use runtime::vm::encoders::store_memory::StoreMemory;
use runtime::vm::encoders::store_register::StoreRegister;
use runtime::vm::encoders::sub::Sub;
use runtime::vm::encoders::xor::Xor;
use runtime::vm::encoders::Encode;

pub mod anti_debug;
pub mod anti_tamper;

pub fn generate(engine: &mut Engine, key: u64) -> Vec<Vec<Rc<dyn Encode>>> {
    let mut rng = rand::thread_rng();

    let mut blocks = Vec::<Vec<Rc<dyn Encode>>>::new();

    let mut block = Vec::<Rc<dyn Encode>>::new();

    let mut vp0 = 0;
    block.extend(anti_debug::generate(engine, &mut rng, &mut vp0));
    let mut vp1 = 0;
    block.extend(anti_tamper::generate(engine, &mut rng, &mut vp1));

    block.extend(correct(key, vp0, vp1));
    blocks.push(block);

    blocks
}

fn skip<F: FnOnce(&mut Engine) -> Vec<Rc<dyn Encode>>>(
    engine: &mut Engine,
    register: VMReg,
    condition: VMCondition,
    body: F,
) -> Vec<Rc<dyn Encode>> {
    let body = body(engine);
    let mut instructions = Vec::<Rc<dyn Encode>>::new();
    instructions.push(Rc::new(LoadRegister {
        width: VMWidth::Lower64,
        source: register,
    }));
    instructions.push(Rc::new(LoadRegister {
        width: VMWidth::Lower64,
        source: register,
    }));
    instructions.push(Rc::new(And {
        width: VMWidth::Lower64,
    }));
    instructions.push(Rc::new(Discard));
    instructions.push(Rc::new(Skip::new(
        &mut engine.rt.mapper,
        VMLogic::SAND,
        vec![condition],
        body,
    )));
    instructions
}

enum Bound {
    Immediate(usize),
    Register(VMReg),
}

fn foreach<F: FnOnce() -> Vec<Rc<dyn Encode>>>(
    counter: VMReg,
    bound: Bound,
    step: u64,
    body: F,
) -> Vec<Rc<dyn Encode>> {
    let mut operations = Vec::<Rc<dyn Encode>>::new();
    let mut jumps = Vec::new();

    operations.extend(set(counter, 0));

    let head = operations.len();

    operations.extend(body());

    operations.extend(increment(counter, step));

    operations.push(Rc::new(LoadRegister {
        width: VMWidth::Lower64,
        source: counter,
    }));
    match bound {
        Bound::Immediate(value) => {
            operations.push(Rc::new(LoadImmediate {
                width: VMWidth::Lower64,
                source: (value as u64).to_le_bytes().to_vec(),
            }));
        }
        Bound::Register(reg) => {
            operations.push(Rc::new(LoadRegister {
                width: VMWidth::Lower64,
                source: reg,
            }));
        }
    }
    operations.push(Rc::new(Sub {
        width: VMWidth::Lower64,
    }));
    operations.push(Rc::new(Discard));

    operations.push(Rc::new(LoadImmediate {
        width: VMWidth::SLower16,
        source: vec![0, 0],
    }));
    jumps.push(Jump {
        source: operations.len() - 1,
        destination: Target::Operation(head),
    });
    operations.push(Rc::new(Jcc {
        logic: VMLogic::SAND,
        conditions: vec![VMCondition::cmp(VMFlag::Carry, 1)],
    }));

    vec![Rc::new(Chain::new(operations, jumps))]
}

fn set(register: VMReg, value: u64) -> Vec<Rc<dyn Encode>> {
    vec![
        Rc::new(LoadImmediate {
            width: VMWidth::Lower64,
            source: value.to_le_bytes().to_vec(),
        }),
        Rc::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: register,
        }),
    ]
}

fn copy(source: VMReg, destination: VMReg) -> Vec<Rc<dyn Encode>> {
    vec![
        Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: source,
        }),
        Rc::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: destination,
        }),
    ]
}

fn increment(register: VMReg, amount: u64) -> Vec<Rc<dyn Encode>> {
    vec![
        Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: register,
        }),
        Rc::new(LoadImmediate {
            width: VMWidth::Lower64,
            source: amount.to_le_bytes().to_vec(),
        }),
        Rc::new(Add {
            width: VMWidth::Lower64,
        }),
        Rc::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: register,
        }),
    ]
}

fn reserve(amount: u64) -> Vec<Rc<dyn Encode>> {
    vec![
        Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: VMReg::Rsp,
        }),
        Rc::new(LoadImmediate {
            width: VMWidth::Lower64,
            source: amount.to_le_bytes().to_vec(),
        }),
        Rc::new(Sub {
            width: VMWidth::Lower64,
        }),
        Rc::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: VMReg::Rsp,
        }),
    ]
}

fn release(amount: u64) -> Vec<Rc<dyn Encode>> {
    vec![
        Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: VMReg::Rsp,
        }),
        Rc::new(LoadImmediate {
            width: VMWidth::Lower64,
            source: amount.to_le_bytes().to_vec(),
        }),
        Rc::new(Add {
            width: VMWidth::Lower64,
        }),
        Rc::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: VMReg::Rsp,
        }),
    ]
}

fn invoke(target: VMReg) -> Vec<Rc<dyn Encode>> {
    vec![
        Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: target,
        }),
        Rc::new(Jcc::call()),
    ]
}

fn import(engine: &mut Engine, def: ImportDef) -> Vec<Rc<dyn Encode>> {
    let mut instructions = Vec::<Rc<dyn Encode>>::new();
    instructions.extend(set(VMReg::Rcx, engine.rt.mapper.index(def) as u64));
    instructions.extend(call(engine, FnDef::Resolve));
    instructions
}

fn call(engine: &mut Engine, def: FnDef) -> Vec<Rc<dyn Encode>> {
    let displacement = engine.rt.lookup(engine.rt.function_labels[&def]) as i32;
    vec![
        Rc::new(LoadAddress {
            source: VMMem {
                base: VMReg::VImage,
                index: VMReg::None,
                scale: 1,
                displacement,
                segment: VMSeg::None,
            },
        }),
        Rc::new(Jcc::call()),
    ]
}

fn correct(key: u64, vp0: u64, vp1: u64) -> Vec<Rc<dyn Encode>> {
    let correction = key ^ (vp0 ^ vp1);
    vec![
        Rc::new(LoadAddress {
            source: VMMem {
                base: VMReg::Vg0,
                index: VMReg::None,
                scale: 1,
                displacement: -0x8 - 0x1 - 0x1,
                segment: VMSeg::None,
            },
        }),
        Rc::new(LoadMemory {
            width: VMWidth::Lower64,
        }),
        Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: VMReg::Vp0,
        }),
        Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: VMReg::Vp1,
        }),
        Rc::new(Xor {
            width: VMWidth::Lower64,
        }),
        Rc::new(LoadImmediate {
            width: VMWidth::Lower64,
            source: correction.to_le_bytes().to_vec(),
        }),
        Rc::new(Xor {
            width: VMWidth::Lower64,
        }),
        Rc::new(Xor {
            width: VMWidth::Lower64,
        }),
        Rc::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: VMReg::Vg0,
        }),
    ]
}

fn absolute(index: VMReg, scale: u8, displacement: i32, width: VMWidth) -> Vec<Rc<dyn Encode>> {
    let mut instructions = Vec::<Rc<dyn Encode>>::new();
    instructions.push(Rc::new(LoadAddress {
        source: VMMem {
            base: VMReg::VImage,
            index,
            scale,
            displacement,
            segment: VMSeg::None,
        },
    }));
    instructions.push(Rc::new(LoadMemory { width }));
    instructions.push(Rc::new(LoadRegister {
        width: VMWidth::Lower64,
        source: VMReg::VImage,
    }));
    instructions.push(Rc::new(Add {
        width: VMWidth::Lower64,
    }));
    instructions
}

fn save(dst: VMReg) -> Vec<Rc<dyn Encode>> {
    vec![Rc::new(StoreRegister {
        width: VMWidth::Lower64,
        destination: dst,
    })]
}

fn mask(source: VMReg, mask: u64) -> Vec<Rc<dyn Encode>> {
    vec![
        Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: source,
        }),
        Rc::new(LoadImmediate {
            width: VMWidth::Lower64,
            source: mask.to_le_bytes().to_vec(),
        }),
        Rc::new(And {
            width: VMWidth::Lower64,
        }),
    ]
}

fn sub(a: VMReg, b: VMReg) -> Vec<Rc<dyn Encode>> {
    vec![
        Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: a,
        }),
        Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: b,
        }),
        Rc::new(Sub {
            width: VMWidth::Lower64,
        }),
    ]
}

fn add(a: VMReg, b: VMReg) -> Vec<Rc<dyn Encode>> {
    vec![
        Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: a,
        }),
        Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: b,
        }),
        Rc::new(Add {
            width: VMWidth::Lower64,
        }),
    ]
}

fn compute(base: VMReg, index: VMReg, scale: u8, displacement: i32) -> Vec<Rc<dyn Encode>> {
    vec![Rc::new(LoadAddress {
        source: VMMem {
            base,
            index,
            scale,
            displacement,
            segment: VMSeg::None,
        },
    })]
}

fn load(
    base: VMReg,
    index: VMReg,
    scale: u8,
    displacement: i32,
    width: VMWidth,
) -> Vec<Rc<dyn Encode>> {
    let mut instructions = Vec::<Rc<dyn Encode>>::new();
    instructions.extend(compute(base, index, scale, displacement));
    instructions.push(Rc::new(LoadMemory { width }));
    instructions
}

fn store(
    base: VMReg,
    index: VMReg,
    scale: u8,
    displacement: i32,
    value: u64,
) -> Vec<Rc<dyn Encode>> {
    vec![
        Rc::new(LoadImmediate {
            width: VMWidth::Lower64,
            source: value.to_le_bytes().to_vec(),
        }),
        Rc::new(LoadAddress {
            source: VMMem {
                base,
                index,
                scale,
                displacement,
                segment: VMSeg::None,
            },
        }),
        Rc::new(StoreMemory {
            width: VMWidth::Lower64,
        }),
    ]
}

fn apply(operation: u32, value: u64, expected: &mut u64) {
    match operation {
        0 => *expected = expected.wrapping_add(value),
        1 => *expected = value.wrapping_sub(*expected),
        _ => *expected ^= value,
    }
}

fn create(accumulator: VMReg, operation: u32) -> Vec<Rc<dyn Encode>> {
    let mut instructions = Vec::<Rc<dyn Encode>>::new();
    instructions.push(Rc::new(LoadRegister {
        width: VMWidth::Lower64,
        source: accumulator,
    }));
    match operation {
        0 => instructions.push(Rc::new(Add {
            width: VMWidth::Lower64,
        })),
        1 => instructions.push(Rc::new(Sub {
            width: VMWidth::Lower64,
        })),
        _ => instructions.push(Rc::new(Xor {
            width: VMWidth::Lower64,
        })),
    }
    instructions.push(Rc::new(StoreRegister {
        width: VMWidth::Lower64,
        destination: accumulator,
    }));
    instructions
}

fn accumulate<R: Rng>(
    rng: &mut R,
    accumulator: VMReg,
    source: VMReg,
    value: u64,
    expected: &mut u64,
) -> Vec<Rc<dyn Encode>> {
    let mut instructions = Vec::<Rc<dyn Encode>>::new();
    let operation = rng.gen_range(0..3);
    instructions.push(Rc::new(LoadRegister {
        width: VMWidth::Lower64,
        source: source,
    }));
    instructions.extend(create(accumulator, operation));
    apply(operation, value, expected);
    instructions
}

fn accumulate_memory<R: Rng>(
    rng: &mut R,
    accumulator: VMReg,
    base: VMReg,
    displacement: i32,
    width: VMWidth,
    value: u64,
    expected: &mut u64,
) -> Vec<Rc<dyn Encode>> {
    let mut instructions = Vec::<Rc<dyn Encode>>::new();
    let operation = rng.gen_range(0..3);
    instructions.push(Rc::new(LoadAddress {
        source: VMMem {
            base,
            index: VMReg::None,
            scale: 1,
            displacement,
            segment: VMSeg::None,
        },
    }));
    instructions.push(Rc::new(LoadMemory { width }));
    instructions.extend(create(accumulator, operation));
    apply(operation, value, expected);
    instructions
}

fn accumulate_byte<R: Rng>(
    rng: &mut R,
    accumulator: VMReg,
    base: VMReg,
    displacement: i32,
    value: u64,
    expected: &mut u64,
) -> Vec<Rc<dyn Encode>> {
    accumulate_memory(
        rng,
        accumulator,
        base,
        displacement,
        VMWidth::Lower8,
        value,
        expected,
    )
}

fn accumulate_prologue<R: Rng>(
    rng: &mut R,
    accumulator: VMReg,
    base: VMReg,
    prologue: &[u8; 3],
    expected: &mut u64,
) -> Vec<Rc<dyn Encode>> {
    let mut instructions = Vec::<Rc<dyn Encode>>::new();

    for (offset, byte) in prologue.iter().enumerate() {
        instructions.extend(accumulate_byte(
            rng,
            accumulator,
            base,
            offset as i32,
            *byte as u64,
            expected,
        ));
    }
    instructions
}

#[cfg(debug_assertions)]
fn print(engine: &mut Engine, message: &str, register: Option<VMReg>) -> Vec<Rc<dyn Encode>> {
    const VOLATILE: &[VMReg] = &[
        VMReg::Rax,
        VMReg::Rcx,
        VMReg::Rdx,
        VMReg::R8,
        VMReg::R9,
        VMReg::R10,
        VMReg::R11,
    ];

    let mut instructions = Vec::<Rc<dyn Encode>>::new();

    for &register in VOLATILE {
        instructions.push(Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: register,
        }));
    }

    if let Some(register) = register {
        instructions.push(Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: register,
        }));
    }

    let length = message.len()
        + if register.is_some() {
            1 + 16 + 1 + 1
        } else {
            2
        };

    instructions.extend(reserve(length as u64));

    instructions.extend(write_string(VMReg::Rsp, 0, message));

    let mut offset = message.len();

    if register.is_some() {
        instructions.extend(write_byte(VMReg::Rsp, offset as i32, b' '));

        offset += 1;

        instructions.push(Rc::new(LoadAddress {
            source: VMMem {
                base: VMReg::Rsp,
                index: VMReg::None,
                scale: 1,
                displacement: offset as i32,
                segment: VMSeg::None,
            },
        }));
        instructions.push(Rc::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: VMReg::Rcx,
        }));
        instructions.push(Rc::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: VMReg::Rdx,
        }));
        instructions.extend(call(engine, FnDef::Format));

        instructions.extend(write_byte(VMReg::Rsp, (offset + 16) as i32, b'\n'));
        instructions.extend(write_byte(VMReg::Rsp, (offset + 17) as i32, 0));
    } else {
        instructions.extend(write_byte(VMReg::Rsp, offset as i32, b'\n'));
        instructions.extend(write_byte(VMReg::Rsp, (offset + 1) as i32, 0));
    }

    instructions.push(Rc::new(LoadAddress {
        source: VMMem {
            base: VMReg::Rsp,
            index: VMReg::None,
            scale: 1,
            displacement: 0,
            segment: VMSeg::None,
        },
    }));
    instructions.push(Rc::new(StoreRegister {
        width: VMWidth::Lower64,
        destination: VMReg::Rcx,
    }));
    instructions.extend(call(engine, FnDef::Print));

    instructions.extend(release(length as u64));

    for &register in VOLATILE.iter().rev() {
        instructions.push(Rc::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: register,
        }));
    }

    instructions
}

fn write_byte(base: VMReg, displacement: i32, byte: u8) -> Vec<Rc<dyn Encode>> {
    vec![
        Rc::new(LoadImmediate {
            width: VMWidth::Lower8,
            source: vec![byte],
        }),
        Rc::new(LoadAddress {
            source: VMMem {
                base,
                index: VMReg::None,
                scale: 1,
                displacement,
                segment: VMSeg::None,
            },
        }),
        Rc::new(StoreMemory {
            width: VMWidth::Lower8,
        }),
    ]
}

fn write_bytes(base: VMReg, displacement: i32, bytes: &[u8]) -> Vec<Rc<dyn Encode>> {
    let mut instructions = Vec::new();

    for (i, &b) in bytes.iter().enumerate() {
        instructions.extend(write_byte(base, displacement + i as i32, b));
    }
    instructions
}

fn write_string(base: VMReg, displacement: i32, string: &str) -> Vec<Rc<dyn Encode>> {
    write_bytes(base, displacement, string.as_bytes())
}
