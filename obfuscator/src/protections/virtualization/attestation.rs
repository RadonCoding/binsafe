use std::rc::Rc;
use std::{convert::TryInto, i32};

use crate::engine::Engine;
use exe::{Buffer, PE, RVA};
use rand::Rng;
use runtime::mapper::Mappable;
use runtime::runtime::{FnDef, ImportDef};
use runtime::vm::bytecode::{VMCondition, VMFlag, VMLogic, VMMem, VMReg, VMSeg, VMWidth};
use runtime::vm::encoders::add::Add;
use runtime::vm::encoders::and::And;
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

const NT_SET_INFORMATION_THREAD_PROLOGUE: [u8; 3] = [0x4C, 0x8B, 0xD1];
const NT_QUERY_INFORMATION_THREAD_PROLOGUE: [u8; 3] = [0x4C, 0x8B, 0xD1];
const NT_CURRENT_THREAD: i64 = -2;
const THREAD_HIDE_FROM_DEBUGGER: u64 = 0x11;
const ACCUMULATOR: VMReg = VMReg::R13;
const NT_SET_INFORMATION_THREAD: VMReg = VMReg::R14;
const NT_QUERY_INFORMATION_THREAD: VMReg = VMReg::R15;

pub fn generate(engine: &mut Engine, key: u64) -> Vec<Vec<Rc<dyn Encode>>> {
    let mut rng = rand::thread_rng();

    let mut expected = 0;

    let mut blocks = Vec::<Vec<Rc<dyn Encode>>>::new();

    let mut block = Vec::<Rc<dyn Encode>>::new();

    block.extend(preserve());

    // for &function in FnDef::VARIANTS {
    //     let rva = engine.rt.lookup(engine.rt.function_labels[&function]) as u32;
    //     let size = engine.rt.size(engine.rt.function_labels[&function]) as usize;

    //     let offset = engine.pe.translate(RVA(rva).into()).unwrap();
    //     let bytes = engine.pe.read(offset, size).unwrap();

    //     let mut current = 0;

    //     while current < size && (rva as usize + current) % 8 != 0 {
    //         block.extend(accumulate_memory(
    //             &mut rng,
    //             VMReg::VImage,
    //             (rva as usize + current) as i32,
    //             VMWidth::Lower8,
    //             bytes[current] as u64,
    //             &mut expected,
    //         ));
    //         current += 1;
    //     }

    //     while current + 8 <= size {
    //         let value = u64::from_le_bytes(bytes[current..current + 8].try_into().unwrap());
    //         block.extend(accumulate_memory(
    //             &mut rng,
    //             VMReg::VImage,
    //             (rva as usize + current) as i32,
    //             VMWidth::Lower64,
    //             value,
    //             &mut expected,
    //         ));
    //         current += 8;
    //     }

    //     while current < size {
    //         block.extend(accumulate_memory(
    //             &mut rng,
    //             VMReg::VImage,
    //             (rva as usize + current) as i32,
    //             VMWidth::Lower8,
    //             bytes[current] as u64,
    //             &mut expected,
    //         ));
    //         current += 1;
    //     }
    // }

    block.extend(skip(engine, VMReg::Vp0, |engine| {
        let mut b = Vec::<Rc<dyn Encode>>::new();
        b.extend(set(ACCUMULATOR, 0));
        b.extend(import(engine, ImportDef::NtSetInformationThread));
        b.extend(copy(VMReg::Rax, NT_SET_INFORMATION_THREAD));
        b.extend(accumulate_prologue(
            &mut rng,
            NT_SET_INFORMATION_THREAD,
            &NT_SET_INFORMATION_THREAD_PROLOGUE,
            &mut expected,
        ));
        b.extend(import(engine, ImportDef::NtQueryInformationThread));
        b.extend(copy(VMReg::Rax, NT_QUERY_INFORMATION_THREAD));
        b.extend(accumulate_prologue(
            &mut rng,
            NT_QUERY_INFORMATION_THREAD,
            &NT_QUERY_INFORMATION_THREAD_PROLOGUE,
            &mut expected,
        ));
        b.extend(set(VMReg::Rcx, NT_CURRENT_THREAD as u64));
        b.extend(set(VMReg::Rdx, THREAD_HIDE_FROM_DEBUGGER));
        b.extend(set(VMReg::R8, 0));
        b.extend(set(VMReg::R9, 0));
        b.extend(invoke(NT_SET_INFORMATION_THREAD));
        b.extend(accumulate(&mut rng, VMReg::Rax, 0, &mut expected));
        b.push(Rc::new(LoadImmediate {
            width: VMWidth::Lower64,
            source: 0u64.to_le_bytes().to_vec(),
        }));
        b.push(Rc::new(LoadAddress {
            source: VMMem {
                base: VMReg::VScratch,
                index: VMReg::None,
                scale: 1,
                displacement: 0,
                segment: VMSeg::None,
            },
        }));
        b.push(Rc::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: VMReg::R8,
        }));
        b.extend(set(VMReg::Rcx, NT_CURRENT_THREAD as u64));
        b.extend(set(VMReg::Rdx, THREAD_HIDE_FROM_DEBUGGER));
        b.extend(set(VMReg::R9, 1));
        b.extend(store(VMReg::Rsp, 0x20, 0));
        b.extend(invoke(NT_QUERY_INFORMATION_THREAD));
        b.extend(accumulate(&mut rng, VMReg::Rax, 0, &mut expected));
        b.extend(accumulate_byte(
            &mut rng,
            VMReg::VScratch,
            0,
            1,
            &mut expected,
        ));
        b.push(Rc::new(Discard));
        b.extend(copy(ACCUMULATOR, VMReg::Vp0));
        b
    }));
    block.extend(correct(key, expected));
    block.extend(restore());
    blocks.push(block);
    blocks
}

fn skip<F: FnOnce(&mut Engine) -> Vec<Rc<dyn Encode>>>(
    engine: &mut Engine,
    flag: VMReg,
    body: F,
) -> Vec<Rc<dyn Encode>> {
    let body = body(engine);
    let mut instructions = Vec::<Rc<dyn Encode>>::new();
    instructions.push(Rc::new(LoadRegister {
        width: VMWidth::Lower64,
        source: flag,
    }));
    instructions.push(Rc::new(LoadRegister {
        width: VMWidth::Lower64,
        source: flag,
    }));
    instructions.push(Rc::new(And {
        width: VMWidth::Lower64,
    }));
    instructions.push(Rc::new(Discard));
    instructions.push(Rc::new(Skip::new(
        &mut engine.rt.mapper,
        VMLogic::SAND,
        vec![VMCondition::cmp(VMFlag::Zero, 0)],
        body,
    )));
    instructions
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

fn accumulate<R: Rng>(
    rng: &mut R,
    src: VMReg,
    value: u64,
    expected: &mut u64,
) -> Vec<Rc<dyn Encode>> {
    let mut instructions = Vec::<Rc<dyn Encode>>::new();
    instructions.push(Rc::new(LoadRegister {
        width: VMWidth::Lower64,
        source: src,
    }));
    instructions.push(Rc::new(LoadRegister {
        width: VMWidth::Lower64,
        source: ACCUMULATOR,
    }));
    match rng.gen_range(0..3) {
        0 => {
            instructions.push(Rc::new(Add {
                width: VMWidth::Lower64,
            }));
            *expected = expected.wrapping_add(value);
        }
        1 => {
            instructions.push(Rc::new(Sub {
                width: VMWidth::Lower64,
            }));
            *expected = value.wrapping_sub(*expected);
        }
        _ => {
            instructions.push(Rc::new(Xor {
                width: VMWidth::Lower64,
            }));
            *expected ^= value;
        }
    }
    instructions.push(Rc::new(StoreRegister {
        width: VMWidth::Lower64,
        destination: ACCUMULATOR,
    }));
    instructions
}

fn accumulate_memory<R: Rng>(
    rng: &mut R,
    base: VMReg,
    displacement: i32,
    width: VMWidth,
    value: u64,
    expected: &mut u64,
) -> Vec<Rc<dyn Encode>> {
    let mut instructions = Vec::<Rc<dyn Encode>>::new();
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
    instructions.push(Rc::new(LoadRegister {
        width: VMWidth::Lower64,
        source: ACCUMULATOR,
    }));
    match rng.gen_range(0..3) {
        0 => {
            instructions.push(Rc::new(Add {
                width: VMWidth::Lower64,
            }));
            *expected = expected.wrapping_add(value);
        }
        1 => {
            instructions.push(Rc::new(Sub {
                width: VMWidth::Lower64,
            }));
            *expected = value.wrapping_sub(*expected);
        }
        _ => {
            instructions.push(Rc::new(Xor {
                width: VMWidth::Lower64,
            }));
            *expected ^= value;
        }
    }
    instructions.push(Rc::new(StoreRegister {
        width: VMWidth::Lower64,
        destination: ACCUMULATOR,
    }));
    instructions
}

fn accumulate_byte<R: Rng>(
    rng: &mut R,
    base: VMReg,
    displacement: i32,
    value: u64,
    expected: &mut u64,
) -> Vec<Rc<dyn Encode>> {
    accumulate_memory(rng, base, displacement, VMWidth::Lower8, value, expected)
}

fn accumulate_prologue<R: Rng>(
    rng: &mut R,
    base: VMReg,
    prologue: &[u8; 3],
    expected: &mut u64,
) -> Vec<Rc<dyn Encode>> {
    let mut instructions = Vec::<Rc<dyn Encode>>::new();
    for (offset, byte) in prologue.iter().enumerate() {
        instructions.extend(accumulate_byte(
            rng,
            base,
            offset as i32,
            *byte as u64,
            expected,
        ));
    }
    instructions
}

fn preserve() -> Vec<Rc<dyn Encode>> {
    let mut instructions = Vec::<Rc<dyn Encode>>::new();
    instructions.extend(reserve(0x28));
    instructions
}

fn restore() -> Vec<Rc<dyn Encode>> {
    let mut instructions = Vec::<Rc<dyn Encode>>::new();
    instructions.extend(release(0x28));
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

fn correct(key: u64, expected: u64) -> Vec<Rc<dyn Encode>> {
    let correction = key ^ expected;
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
