use crate::engine::Engine;
use runtime::runtime::{DataDef, FnDef, ImportDef};
use runtime::vm::bytecode::{VMCondition, VMFlag, VMLogic, VMMem, VMReg, VMSeg, VMVec, VMWidth};
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
use runtime::vm::encoders::load_vector::LoadVector;
use runtime::vm::encoders::mul::Mul;
use runtime::vm::encoders::or::Or;
use runtime::vm::encoders::shl::Shl;
use runtime::vm::encoders::shr::Shr;
use runtime::vm::encoders::skip::Skip;
use runtime::vm::encoders::store_memory::StoreMemory;
use runtime::vm::encoders::store_merge::StoreMerge;
use runtime::vm::encoders::store_register::StoreRegister;
use runtime::vm::encoders::sub::Sub;
use runtime::vm::encoders::timestamp::Timestamp;
use runtime::vm::encoders::xor::Xor;
use runtime::vm::encoders::Encode;

pub enum Bound {
    Immediate(usize),
    Register(VMReg),
}

pub fn immediate(value: u64) -> Vec<Box<dyn Encode>> {
    vec![Box::new(LoadImmediate {
        width: VMWidth::Lower64,
        source: value.to_le_bytes().to_vec(),
    })]
}

pub fn skip<F: FnOnce(&mut Engine) -> Vec<Box<dyn Encode>>>(
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

pub fn foreach<F: FnOnce() -> Vec<Box<dyn Encode>>>(
    counter: VMReg,
    bound: Bound,
    step: u64,
    body: F,
) -> Vec<Box<dyn Encode>> {
    let mut operations = Vec::<Box<dyn Encode>>::new();

    let mut jumps = Vec::new();

    operations.extend(set_register(counter, 0));

    let destination = Label::target();

    operations.push(Box::new(destination));

    operations.extend(body());
    operations.extend(increment(counter, step));
    operations.extend(spill_register(counter));
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

    let source = Label::marker();

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

pub fn data(engine: &mut Engine, def: DataDef) -> Vec<Box<dyn Encode>> {
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

pub fn timestamp() -> Vec<Box<dyn Encode>> {
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

pub fn set_register(register: VMReg, value: u64) -> Vec<Box<dyn Encode>> {
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

pub fn set_vector(destination: VMVec, lo: u64, hi: u64) -> Vec<Box<dyn Encode>> {
    let mut instructions: Vec<Box<dyn Encode>> = Vec::<Box<dyn Encode>>::new();

    instructions.push(Box::new(LoadImmediate {
        width: VMWidth::Lower64,
        source: lo.to_le_bytes().to_vec(),
    }));
    instructions.push(Box::new(LoadImmediate {
        width: VMWidth::Lower64,
        source: hi.to_le_bytes().to_vec(),
    }));
    instructions.push(Box::new(StoreMerge {
        width: VMWidth::Lower128,
        destination,
    }));
    instructions
}

pub fn copy(source: VMReg, destination: VMReg) -> Vec<Box<dyn Encode>> {
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

pub fn increment(register: VMReg, amount: u64) -> Vec<Box<dyn Encode>> {
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

pub fn reserve(amount: u64) -> Vec<Box<dyn Encode>> {
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

pub fn release(amount: u64) -> Vec<Box<dyn Encode>> {
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

pub fn invoke(target: VMReg) -> Vec<Box<dyn Encode>> {
    vec![
        Box::new(LoadRegister {
            width: VMWidth::Lower64,
            source: target,
        }),
        Box::new(Jcc::call()),
    ]
}

pub fn import(engine: &mut Engine, def: ImportDef) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();
    instructions.extend(set_register(VMReg::Rcx, engine.rt.mapper.index(def) as u64));
    instructions.extend(call(engine, FnDef::Resolve));
    instructions
}

pub fn call(engine: &mut Engine, def: FnDef) -> Vec<Box<dyn Encode>> {
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

pub fn spill_register(source: VMReg) -> Vec<Box<dyn Encode>> {
    vec![Box::new(LoadRegister {
        width: VMWidth::Lower64,
        source,
    })]
}

pub fn spill_vector(source: VMVec, width: VMWidth) -> Vec<Box<dyn Encode>> {
    vec![Box::new(LoadVector { width, source })]
}

pub fn reload_register(destination: VMReg) -> Vec<Box<dyn Encode>> {
    vec![Box::new(StoreRegister {
        width: VMWidth::Lower64,
        destination,
    })]
}

pub fn reload_vector(destination: VMVec, width: VMWidth) -> Vec<Box<dyn Encode>> {
    vec![Box::new(StoreMerge { width, destination })]
}

pub fn mask(source: Option<VMReg>, mask: u64) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();

    if let Some(source) = source {
        instructions.push(Box::new(LoadRegister {
            width: VMWidth::Lower64,
            source,
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

pub fn sub(a: Option<VMReg>, b: Option<VMReg>) -> Vec<Box<dyn Encode>> {
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

pub fn add(a: Option<VMReg>, b: Option<VMReg>) -> Vec<Box<dyn Encode>> {
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

pub fn mul(a: Option<VMReg>, b: Option<VMReg>) -> Vec<Box<dyn Encode>> {
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

pub fn xor(a: Option<VMReg>, b: Option<VMReg>) -> Vec<Box<dyn Encode>> {
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

pub fn shr(a: Option<VMReg>, b: Option<VMReg>) -> Vec<Box<dyn Encode>> {
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
    instructions.push(Box::new(Shr {
        width: VMWidth::Lower64,
    }));
    instructions
}

pub fn compute(
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

pub fn load(
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

pub fn store(
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
