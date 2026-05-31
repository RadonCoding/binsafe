use std::rc::Rc;
use runtime::runtime::{FnDef, ImportDef};
use runtime::vm::bytecode::{VMMem, VMReg, VMSeg, VMWidth};
use runtime::vm::encoders::add::Add;
use runtime::vm::encoders::discard::Discard;
use runtime::vm::encoders::jcc::Jcc;
use runtime::vm::encoders::load_address::LoadAddress;
use runtime::vm::encoders::load_immediate::LoadImmediate;
use runtime::vm::encoders::load_memory::LoadMemory;
use runtime::vm::encoders::load_register::LoadRegister;
use runtime::vm::encoders::store_memory::StoreMemory;
use runtime::vm::encoders::store_register::StoreRegister;
use runtime::vm::encoders::sub::Sub;
use runtime::vm::encoders::Encode;

use crate::engine::Engine;

const NT_SET_INFORMATION_THREAD_PROLOGUE: [u8; 3] = [0x4C, 0x8B, 0xD1];
const NT_QUERY_INFORMATION_THREAD_PROLOGUE: [u8; 3] = [0x4C, 0x8B, 0xD1];

const NT_CURRENT_THREAD: i64 = -2;
const THREAD_HIDE_FROM_DEBUGGER: u64 = 0x11;

const SHADOW_SPACE: u64 = 0x20;

const RETURN_LENGTH_SIZE: u64 = 0x10;

const ACCUMULATOR: VMReg = VMReg::R12;
const NT_SET_INFORMATION_THREAD: VMReg = VMReg::R13;
const NT_QUERY_INFORMATION_THREAD: VMReg = VMReg::R14;

const PRESERVED: &[VMReg] = &[
    VMReg::Rax,
    VMReg::Rcx,
    VMReg::Rdx,
    VMReg::R8,
    VMReg::R9,
    VMReg::R10,
    VMReg::R11,
    VMReg::Flags,
    ACCUMULATOR,
    NT_SET_INFORMATION_THREAD,
    NT_QUERY_INFORMATION_THREAD,
];

pub fn generate(engine: &mut Engine, key: u64) -> Vec<Vec<Rc<dyn Encode>>> {
    let mut blocks = Vec::<Vec<Rc<dyn Encode>>>::new();

    let mut block = Vec::<Rc<dyn Encode>>::new();
    block.extend(preserve());
    block.extend(set(ACCUMULATOR, 0));
    block.extend(import(engine, ImportDef::NtSetInformationThread));
    blocks.push(block);

    let mut block = Vec::<Rc<dyn Encode>>::new();
    block.extend(copy(VMReg::Rax, NT_SET_INFORMATION_THREAD));
    block.extend(accumulate_prologue(NT_SET_INFORMATION_THREAD));
    block.extend(import(engine, ImportDef::NtQueryInformationThread));
    blocks.push(block);

    let mut block = Vec::<Rc<dyn Encode>>::new();
    block.extend(copy(VMReg::Rax, NT_QUERY_INFORMATION_THREAD));
    block.extend(accumulate_prologue(NT_QUERY_INFORMATION_THREAD));
    // ThreadHandle -> RCX
    block.extend(set(VMReg::Rcx, NT_CURRENT_THREAD as u64));
    // ThreadInformationClass -> RDX
    block.extend(set(VMReg::Rdx, THREAD_HIDE_FROM_DEBUGGER));
    // ThreadInformation -> R8
    block.extend(set(VMReg::R8, 0));
    // ThreadInformationLength -> R9
    block.extend(set(VMReg::R9, 0));
    // NtSetInformationThread
    block.extend(invoke(NT_SET_INFORMATION_THREAD));
    blocks.push(block);

    let mut block = Vec::<Rc<dyn Encode>>::new();
    block.extend(accumulate(VMReg::Rax));
    // ALLOCATE ThreadInformation
    block.push(Rc::new(LoadImmediate {
        width: VMWidth::Lower64,
        source: 0u64.to_le_bytes().to_vec(),
    }));
    block.push(Rc::new(LoadAddress {
        source: VMMem {
            base: VMReg::VScratch,
            index: VMReg::None,
            scale: 1,
            displacement: 0,
            segment: VMSeg::None,
        },
    }));
    // ThreadInformation -> R8
    block.push(Rc::new(StoreRegister {
        width: VMWidth::Lower64,
        destination: VMReg::R8,
    }));
    // ThreadHandle -> RCX
    block.extend(set(VMReg::Rcx, NT_CURRENT_THREAD as u64));
    // ThreadInformationClass -> RDX
    block.extend(set(VMReg::Rdx, THREAD_HIDE_FROM_DEBUGGER));
    // ThreadInformationLength -> R9
    block.extend(set(VMReg::R9, 1));
    // RESERVE ReturnLength
    block.extend(reserve(RETURN_LENGTH_SIZE));
    // ReturnLength -> [RSP + ...]
    block.extend(store(VMReg::Rsp, SHADOW_SPACE as i32, 0));
    // NtQueryInformationThread
    block.extend(invoke(NT_QUERY_INFORMATION_THREAD));
    blocks.push(block);

    let mut block = Vec::<Rc<dyn Encode>>::new();
    // RELEASE ReturnLength
    block.extend(release(RETURN_LENGTH_SIZE));
    // ACCUMULATE RAX
    block.extend(accumulate(VMReg::Rax));
    // READ ThreadInformation[0]
    block.extend(accumulate_byte(VMReg::VScratch, 0));
    // DISCARD ThreadInformation
    block.push(Rc::new(Discard));
    block.extend(correct(key));
    block.extend(restore());
    blocks.push(block);

    blocks
}

fn set(dst: VMReg, value: u64) -> Vec<Rc<dyn Encode>> {
    vec![
        Rc::new(LoadImmediate {
            width: VMWidth::Lower64,
            source: value.to_le_bytes().to_vec(),
        }),
        Rc::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: dst,
        }),
    ]
}

fn copy(src: VMReg, dst: VMReg) -> Vec<Rc<dyn Encode>> {
    vec![
        Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: src,
        }),
        Rc::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: dst,
        }),
    ]
}

fn accumulate(src: VMReg) -> Vec<Rc<dyn Encode>> {
    vec![
        Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: src,
        }),
        Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: ACCUMULATOR,
        }),
        Rc::new(Add {
            width: VMWidth::Lower64,
        }),
        Rc::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: ACCUMULATOR,
        }),
    ]
}

fn accumulate_byte(base: VMReg, displacement: i32) -> Vec<Rc<dyn Encode>> {
    vec![
        Rc::new(LoadAddress {
            source: VMMem {
                base,
                index: VMReg::None,
                scale: 0,
                displacement,
                segment: VMSeg::None,
            },
        }),
        Rc::new(LoadMemory {
            width: VMWidth::Lower8,
        }),
        Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: ACCUMULATOR,
        }),
        Rc::new(Add {
            width: VMWidth::Lower64,
        }),
        Rc::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: ACCUMULATOR,
        }),
    ]
}

fn accumulate_prologue(base: VMReg) -> Vec<Rc<dyn Encode>> {
    let mut instructions = Vec::<Rc<dyn Encode>>::new();
    for offset in 0..3 {
        instructions.extend(accumulate_byte(base, offset));
    }
    instructions
}

fn preserve() -> Vec<Rc<dyn Encode>> {
    let mut instructions = Vec::<Rc<dyn Encode>>::new();

    for reg in PRESERVED.iter() {
        instructions.push(Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: *reg,
        }));
    }

    instructions.extend(reserve(SHADOW_SPACE));

    instructions
}

fn restore() -> Vec<Rc<dyn Encode>> {
    let mut instructions = Vec::<Rc<dyn Encode>>::new();

    instructions.extend(release(SHADOW_SPACE));

    for reg in PRESERVED.iter().rev() {
        instructions.push(Rc::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: *reg,
        }));
    }

    instructions
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

fn store(base: VMReg, displacement: i32, value: u64) -> Vec<Rc<dyn Encode>> {
    vec![
        Rc::new(LoadImmediate {
            width: VMWidth::Lower64,
            source: value.to_le_bytes().to_vec(),
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
            width: VMWidth::Lower64,
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

fn correct(key: u64) -> Vec<Rc<dyn Encode>> {
    let prologues = NT_SET_INFORMATION_THREAD_PROLOGUE
        .iter()
        .chain(NT_QUERY_INFORMATION_THREAD_PROLOGUE.iter())
        .map(|b| *b as u64)
        .sum::<u64>();
    let expected = prologues + 1;
    let correction = key.wrapping_sub(expected);

    vec![
        Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: ACCUMULATOR,
        }),
        Rc::new(LoadImmediate {
            width: VMWidth::Lower64,
            source: correction.to_le_bytes().to_vec(),
        }),
        Rc::new(Add {
            width: VMWidth::Lower64,
        }),
        Rc::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: VMReg::VAtt,
        }),
    ]
}

fn import(engine: &mut Engine, def: ImportDef) -> Vec<Rc<dyn Encode>> {
    let mut instructions = Vec::<Rc<dyn Encode>>::new();

    instructions.extend(set(VMReg::Rcx, engine.rt.mapper.index(def) as u64));
    instructions.extend(call(engine, FnDef::Resolve));

    instructions
}

fn call(engine: &mut Engine, def: FnDef) -> Vec<Rc<dyn Encode>> {
    vec![
        Rc::new(LoadAddress {
            source: VMMem {
                base: VMReg::VImage,
                index: VMReg::None,
                scale: 1,
                displacement: engine.runtime_address(def),
                segment: VMSeg::None,
            },
        }),
        Rc::new(LoadMemory {
            width: VMWidth::Lower64,
        }),
        Rc::new(Jcc::call()),
    ]
}
