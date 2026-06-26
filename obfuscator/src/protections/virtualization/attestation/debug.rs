#![allow(unused)]

use std::i32;

use crate::engine::Engine;
use crate::protections::virtualization::attestation::*;
use runtime::runtime::FnDef;
use runtime::vm::bytecode::{VMMem, VMReg, VMSeg, VMWidth};
use runtime::vm::encoders::load_address::LoadAddress;
use runtime::vm::encoders::load_immediate::LoadImmediate;
use runtime::vm::encoders::load_register::LoadRegister;
use runtime::vm::encoders::pop::Pop;
use runtime::vm::encoders::push::Push;
use runtime::vm::encoders::store_memory::StoreMemory;
use runtime::vm::encoders::store_register::StoreRegister;
use runtime::vm::encoders::Encode;

pub fn print(engine: &mut Engine, message: &str, register: Option<VMReg>) -> Vec<Box<dyn Encode>> {
    const VOLATILE: &[VMReg] = &[
        VMReg::Rax,
        VMReg::Rcx,
        VMReg::Rdx,
        VMReg::R8,
        VMReg::R9,
        VMReg::R10,
        VMReg::R11,
    ];

    let mut instructions = Vec::<Box<dyn Encode>>::new();

    for &register in VOLATILE {
        instructions.extend(spill_register(register));
    }

    if let Some(register) = register {
        instructions.extend(spill_register(register));
    }

    let length = (message.len() + if register.is_some() { 19 } else { 2 } + 15) & !15;

    instructions.extend(reserve(length as u64));

    instructions.extend(write_string(VMReg::Rsp, 0, message));

    let mut offset = message.len();

    if register.is_some() {
        instructions.extend(write_byte(VMReg::Rsp, offset as i32, b' '));

        offset += 1;

        instructions.extend(compute_memory(
            VMReg::Rsp,
            VMReg::None,
            1,
            offset as i32,
            VMSeg::None,
        ));
        instructions.extend(reload_register(VMReg::Rcx));
        instructions.extend(reload_register(VMReg::Rdx));
        instructions.extend(call(engine, FnDef::Format));

        offset += 16;

        instructions.extend(write_byte(VMReg::Rsp, offset as i32, b'\n'));
        instructions.extend(write_byte(VMReg::Rsp, (offset + 1) as i32, 0));
    } else {
        instructions.extend(write_byte(VMReg::Rsp, offset as i32, b'\n'));
        instructions.extend(write_byte(VMReg::Rsp, (offset + 1) as i32, 0));
    }

    instructions.extend(compute_memory(VMReg::Rsp, VMReg::None, 1, 0, VMSeg::None));
    instructions.extend(reload_register(VMReg::Rcx));
    instructions.extend(call(engine, FnDef::Print));

    instructions.extend(release(length as u64));

    for &register in VOLATILE.iter().rev() {
        instructions.extend(reload_register(register));
    }

    instructions
}

fn write_byte(base: VMReg, displacement: i32, byte: u8) -> Vec<Box<dyn Encode>> {
    vec![
        Box::new(LoadImmediate {
            width: VMWidth::Lower8,
            source: vec![byte],
        }),
        Box::new(LoadAddress {
            source: VMMem {
                base,
                index: VMReg::None,
                scale: 1,
                displacement,
                segment: VMSeg::None,
            },
        }),
        Box::new(StoreMemory {
            width: VMWidth::Lower8,
        }),
    ]
}

fn write_bytes(base: VMReg, displacement: i32, bytes: &[u8]) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::new();

    for (i, &b) in bytes.iter().enumerate() {
        instructions.extend(write_byte(base, displacement + i as i32, b));
    }
    instructions
}

fn write_string(base: VMReg, displacement: i32, string: &str) -> Vec<Box<dyn Encode>> {
    write_bytes(base, displacement, string.as_bytes())
}
