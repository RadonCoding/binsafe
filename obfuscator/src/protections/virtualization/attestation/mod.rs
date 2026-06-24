use std::i32;

use crate::engine::Engine;
use rand::Rng;
use runtime::runtime::{DataDef, FnDef, ImportDef};
use runtime::vm::bytecode::{VMCondition, VMFlag, VMLogic, VMMem, VMReg, VMSeg, VMWidth};
use runtime::vm::encoders::add::Add;
use runtime::vm::encoders::and::And;
use runtime::vm::encoders::chain::{Chain, Jump, Target};
use runtime::vm::encoders::discard::Discard;
use runtime::vm::encoders::jcc::Jcc;
use runtime::vm::encoders::label::Label;
use runtime::vm::encoders::load_address::LoadAddress;
use runtime::vm::encoders::load_immediate::LoadImmediate;
use runtime::vm::encoders::load_memory::LoadMemory;
use runtime::vm::encoders::load_register::LoadRegister;
use runtime::vm::encoders::mul::Mul;
use runtime::vm::encoders::or::Or;
use runtime::vm::encoders::shl::Shl;
use runtime::vm::encoders::skip::Skip;
use runtime::vm::encoders::store_memory::StoreMemory;
use runtime::vm::encoders::store_register::StoreRegister;
use runtime::vm::encoders::sub::Sub;
use runtime::vm::encoders::timestamp::Timestamp;
use runtime::vm::encoders::xor::Xor;
use runtime::vm::encoders::Encode;

mod anti_debug;
mod anti_tamper;
#[cfg(debug_assertions)]
mod debug;

// Masks lower 34 bits of timestamp, creating a ~5s window on a 3.5 GHz CPU
const WINDOW: u64 = 0x22;

pub fn generate(engine: &mut Engine, key: u64) -> Vec<Vec<Box<dyn Encode>>> {
    let mut rng = rand::thread_rng();

    let mut blocks = Vec::<Vec<Box<dyn Encode>>>::new();

    let mut block = Vec::<Box<dyn Encode>>::new();

    block.extend(timestamp());
    block.extend(mask(None, !((1u64 << WINDOW) - 1)));

    block.extend(data(engine, DataDef::VmKeyMul));
    block.extend(mul(None, None));

    block.extend(data(engine, DataDef::VmKeyAdd));
    block.extend(add(None, None));

    block.extend(reload(VMReg::Vt0));

    block.extend(sub(Some(VMReg::Vt0), Some(VMReg::Vt1)));
    block.extend(reload(VMReg::Rax));

    let mut vp0 = 0;
    let mut vp1 = 0;

    block.extend(skip(
        engine,
        VMReg::Rax,
        VMCondition::cmp(VMFlag::Zero, 1),
        |engine| {
            let mut b = Vec::<Box<dyn Encode>>::new();

            b.extend(anti_debug::generate(engine, &mut rng, &mut vp0));
            b.extend(anti_tamper::generate(engine, &mut rng, &mut vp1));

            b.extend(copy(VMReg::Vt0, VMReg::Vt1));

            b
        },
    ));

    block.extend(correct(key, vp0, vp1));

    blocks.push(block);

    blocks
}

fn correct(key: u64, vp0: u64, vp1: u64) -> Vec<Box<dyn Encode>> {
    let correction = key ^ (vp0 ^ vp1);
    vec![
        Box::new(LoadAddress {
            source: VMMem {
                base: VMReg::Vg0,
                index: VMReg::None,
                scale: 1,
                displacement: -0x8 - 0x1 - 0x1,
                segment: VMSeg::None,
            },
        }),
        Box::new(LoadMemory {
            width: VMWidth::Lower64,
        }),
        Box::new(LoadRegister {
            width: VMWidth::Lower64,
            source: VMReg::Vp0,
        }),
        Box::new(LoadRegister {
            width: VMWidth::Lower64,
            source: VMReg::Vt0,
        }),
        Box::new(Xor {
            width: VMWidth::Lower64,
        }),
        Box::new(LoadRegister {
            width: VMWidth::Lower64,
            source: VMReg::Vp1,
        }),
        Box::new(LoadRegister {
            width: VMWidth::Lower64,
            source: VMReg::Vt0,
        }),
        Box::new(Xor {
            width: VMWidth::Lower64,
        }),
        Box::new(Xor {
            width: VMWidth::Lower64,
        }),
        Box::new(LoadImmediate {
            width: VMWidth::Lower64,
            source: correction.to_le_bytes().to_vec(),
        }),
        Box::new(Xor {
            width: VMWidth::Lower64,
        }),
        Box::new(Xor {
            width: VMWidth::Lower64,
        }),
        Box::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: VMReg::Vg0,
        }),
    ]
}

fn skip<F: FnOnce(&mut Engine) -> Vec<Box<dyn Encode>>>(
    engine: &mut Engine,
    register: VMReg,
    condition: VMCondition,
    body: F,
) -> Vec<Box<dyn Encode>> {
    let body = body(engine);
    let mut instructions = Vec::<Box<dyn Encode>>::new();
    instructions.push(Box::new(LoadRegister {
        width: VMWidth::Lower64,
        source: register,
    }));
    instructions.push(Box::new(LoadRegister {
        width: VMWidth::Lower64,
        source: register,
    }));
    instructions.push(Box::new(And {
        width: VMWidth::Lower64,
    }));
    instructions.push(Box::new(Discard));
    instructions.push(Box::new(Skip::new(
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

fn foreach<F: FnOnce() -> Vec<Box<dyn Encode>>>(
    counter: VMReg,
    bound: Bound,
    step: u64,
    body: F,
) -> Vec<Box<dyn Encode>> {
    let mut operations = Vec::<Box<dyn Encode>>::new();

    let mut jumps = Vec::new();

    operations.extend(set(counter, 0));

    let destination = Label::new();

    operations.push(Box::new(destination));

    operations.extend(body());
    operations.extend(increment(counter, step));
    operations.extend(spill(counter));
    match bound {
        Bound::Immediate(value) => {
            operations.push(Box::new(LoadImmediate {
                width: VMWidth::Lower64,
                source: (value as u64).to_le_bytes().to_vec(),
            }));
        }
        Bound::Register(reg) => {
            operations.push(Box::new(LoadRegister {
                width: VMWidth::Lower64,
                source: reg,
            }));
        }
    }
    operations.push(Box::new(Sub {
        width: VMWidth::Lower64,
    }));
    operations.push(Box::new(Discard));

    let source = Label::new();

    operations.push(Box::new(source));

    operations.push(Box::new(LoadImmediate {
        width: VMWidth::SLower16,
        source: vec![0, 0],
    }));
    operations.push(Box::new(Jcc {
        logic: VMLogic::SAND,
        conditions: vec![VMCondition::cmp(VMFlag::Carry, 1)],
    }));

    jumps.push(Jump {
        source,
        destination: Target::Label(destination),
    });

    vec![Box::new(Chain::new(operations, jumps))]
}

fn data(engine: &mut Engine, def: DataDef) -> Vec<Box<dyn Encode>> {
    let displacement = engine.rt.lookup(engine.rt.data_labels[&def]) as i32;
    load(
        VMReg::VImage,
        VMReg::None,
        1,
        displacement,
        VMSeg::None,
        VMWidth::Lower64,
    )
}

fn timestamp() -> Vec<Box<dyn Encode>> {
    vec![
        Box::new(Timestamp),
        Box::new(LoadImmediate {
            width: VMWidth::Lower64,
            source: 0x20u64.to_le_bytes().to_vec(),
        }),
        Box::new(Shl {
            width: VMWidth::Lower64,
        }),
        Box::new(Or {
            width: VMWidth::Lower64,
        }),
    ]
}

fn set(register: VMReg, value: u64) -> Vec<Box<dyn Encode>> {
    vec![
        Box::new(LoadImmediate {
            width: VMWidth::Lower64,
            source: value.to_le_bytes().to_vec(),
        }),
        Box::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: register,
        }),
    ]
}

fn copy(source: VMReg, destination: VMReg) -> Vec<Box<dyn Encode>> {
    vec![
        Box::new(LoadRegister {
            width: VMWidth::Lower64,
            source: source,
        }),
        Box::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: destination,
        }),
    ]
}

fn increment(register: VMReg, amount: u64) -> Vec<Box<dyn Encode>> {
    vec![
        Box::new(LoadRegister {
            width: VMWidth::Lower64,
            source: register,
        }),
        Box::new(LoadImmediate {
            width: VMWidth::Lower64,
            source: amount.to_le_bytes().to_vec(),
        }),
        Box::new(Add {
            width: VMWidth::Lower64,
        }),
        Box::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: register,
        }),
    ]
}

fn reserve(amount: u64) -> Vec<Box<dyn Encode>> {
    vec![
        Box::new(LoadRegister {
            width: VMWidth::Lower64,
            source: VMReg::Rsp,
        }),
        Box::new(LoadImmediate {
            width: VMWidth::Lower64,
            source: amount.to_le_bytes().to_vec(),
        }),
        Box::new(Sub {
            width: VMWidth::Lower64,
        }),
        Box::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: VMReg::Rsp,
        }),
    ]
}

fn release(amount: u64) -> Vec<Box<dyn Encode>> {
    vec![
        Box::new(LoadRegister {
            width: VMWidth::Lower64,
            source: VMReg::Rsp,
        }),
        Box::new(LoadImmediate {
            width: VMWidth::Lower64,
            source: amount.to_le_bytes().to_vec(),
        }),
        Box::new(Add {
            width: VMWidth::Lower64,
        }),
        Box::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: VMReg::Rsp,
        }),
    ]
}

fn invoke(target: VMReg) -> Vec<Box<dyn Encode>> {
    vec![
        Box::new(LoadRegister {
            width: VMWidth::Lower64,
            source: target,
        }),
        Box::new(Jcc::call()),
    ]
}

fn import(engine: &mut Engine, def: ImportDef) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();
    instructions.extend(set(VMReg::Rcx, engine.rt.mapper.index(def) as u64));
    instructions.extend(call(engine, FnDef::Resolve));
    instructions
}

fn call(engine: &mut Engine, def: FnDef) -> Vec<Box<dyn Encode>> {
    let displacement = engine.rt.lookup(engine.rt.function_labels[&def]) as i32;
    vec![
        Box::new(LoadAddress {
            source: VMMem {
                base: VMReg::VImage,
                index: VMReg::None,
                scale: 1,
                displacement,
                segment: VMSeg::None,
            },
        }),
        Box::new(Jcc::call()),
    ]
}

fn absolute(index: VMReg, scale: u8, displacement: i32, width: VMWidth) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();
    instructions.push(Box::new(LoadAddress {
        source: VMMem {
            base: VMReg::VImage,
            index,
            scale,
            displacement,
            segment: VMSeg::None,
        },
    }));
    instructions.push(Box::new(LoadMemory { width }));
    instructions.push(Box::new(LoadRegister {
        width: VMWidth::Lower64,
        source: VMReg::VImage,
    }));
    instructions.push(Box::new(Add {
        width: VMWidth::Lower64,
    }));
    instructions
}

fn spill(source: VMReg) -> Vec<Box<dyn Encode>> {
    vec![Box::new(LoadRegister {
        width: VMWidth::Lower64,
        source,
    })]
}

fn reload(destination: VMReg) -> Vec<Box<dyn Encode>> {
    vec![Box::new(StoreRegister {
        width: VMWidth::Lower64,
        destination,
    })]
}

fn mask(source: Option<VMReg>, mask: u64) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();
    if let Some(reg) = source {
        instructions.push(Box::new(LoadRegister {
            width: VMWidth::Lower64,
            source: reg,
        }));
    }
    instructions.push(Box::new(LoadImmediate {
        width: VMWidth::Lower64,
        source: mask.to_le_bytes().to_vec(),
    }));
    instructions.push(Box::new(And {
        width: VMWidth::Lower64,
    }));
    instructions
}

fn sub(a: Option<VMReg>, b: Option<VMReg>) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();
    if let Some(reg) = a {
        instructions.push(Box::new(LoadRegister {
            width: VMWidth::Lower64,
            source: reg,
        }));
    }
    if let Some(reg) = b {
        instructions.push(Box::new(LoadRegister {
            width: VMWidth::Lower64,
            source: reg,
        }));
    }
    instructions.push(Box::new(Sub {
        width: VMWidth::Lower64,
    }));
    instructions
}

fn add(a: Option<VMReg>, b: Option<VMReg>) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();
    if let Some(reg) = a {
        instructions.push(Box::new(LoadRegister {
            width: VMWidth::Lower64,
            source: reg,
        }));
    }
    if let Some(reg) = b {
        instructions.push(Box::new(LoadRegister {
            width: VMWidth::Lower64,
            source: reg,
        }));
    }
    instructions.push(Box::new(Add {
        width: VMWidth::Lower64,
    }));
    instructions
}

fn mul(a: Option<VMReg>, b: Option<VMReg>) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();
    if let Some(reg) = a {
        instructions.push(Box::new(LoadRegister {
            width: VMWidth::Lower64,
            source: reg,
        }));
    }
    if let Some(reg) = b {
        instructions.push(Box::new(LoadRegister {
            width: VMWidth::Lower64,
            source: reg,
        }));
    }
    instructions.push(Box::new(Mul {
        width: VMWidth::Lower64,
    }));
    instructions.push(Box::new(Discard));
    instructions
}

fn xor(a: Option<VMReg>, b: Option<VMReg>) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();
    if let Some(reg) = a {
        instructions.push(Box::new(LoadRegister {
            width: VMWidth::Lower64,
            source: reg,
        }));
    }
    if let Some(reg) = b {
        instructions.push(Box::new(LoadRegister {
            width: VMWidth::Lower64,
            source: reg,
        }));
    }
    instructions.push(Box::new(Xor {
        width: VMWidth::Lower64,
    }));
    instructions
}

fn compute(
    base: VMReg,
    index: VMReg,
    scale: u8,
    displacement: i32,
    segment: VMSeg,
) -> Vec<Box<dyn Encode>> {
    vec![Box::new(LoadAddress {
        source: VMMem {
            base,
            index,
            scale,
            displacement,
            segment,
        },
    })]
}

fn load(
    base: VMReg,
    index: VMReg,
    scale: u8,
    displacement: i32,
    segment: VMSeg,
    width: VMWidth,
) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();
    instructions.extend(compute(base, index, scale, displacement, segment));
    instructions.push(Box::new(LoadMemory { width }));
    instructions
}

fn store(
    base: VMReg,
    index: VMReg,
    scale: u8,
    displacement: i32,
    value: u64,
) -> Vec<Box<dyn Encode>> {
    vec![
        Box::new(LoadImmediate {
            width: VMWidth::Lower64,
            source: value.to_le_bytes().to_vec(),
        }),
        Box::new(LoadAddress {
            source: VMMem {
                base,
                index,
                scale,
                displacement,
                segment: VMSeg::None,
            },
        }),
        Box::new(StoreMemory {
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

fn create(accumulator: VMReg, operation: u32) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();
    instructions.push(Box::new(LoadRegister {
        width: VMWidth::Lower64,
        source: accumulator,
    }));
    match operation {
        0 => instructions.push(Box::new(Add {
            width: VMWidth::Lower64,
        })),
        1 => instructions.push(Box::new(Sub {
            width: VMWidth::Lower64,
        })),
        _ => instructions.push(Box::new(Xor {
            width: VMWidth::Lower64,
        })),
    }
    instructions.push(Box::new(StoreRegister {
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
) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();
    let operation = rng.gen_range(0..3);
    instructions.push(Box::new(LoadRegister {
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
) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();
    let operation = rng.gen_range(0..3);
    instructions.push(Box::new(LoadAddress {
        source: VMMem {
            base,
            index: VMReg::None,
            scale: 1,
            displacement,
            segment: VMSeg::None,
        },
    }));
    instructions.push(Box::new(LoadMemory { width }));
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
) -> Vec<Box<dyn Encode>> {
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
) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();

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
