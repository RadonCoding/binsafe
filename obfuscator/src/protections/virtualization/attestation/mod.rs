use std::i32;

use crate::engine::Engine;
use crate::protections::virtualization::{crypt, language::*};
use runtime::runtime::{DataDef, ImportDef};
use runtime::vm::bytecode::{Flag, VMCondition, VMReg, VMSeg, VMWidth};
use runtime::vm::encoders::Encode;

mod anti_debug;
mod anti_emulation;
mod anti_tamper;
#[cfg(debug_assertions)]
mod debug;
mod debug_registers;

// Masks the timestamp down to a ~1s tick on a 3.5 GHz CPU
const TICK: u64 = 0x20;

const STALE: u64 = 1u64 << TICK;

pub fn service(engine: &mut Engine, expected: &mut u64) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();

    instructions.extend(anti_debug::generate(engine, expected));
    instructions.extend(anti_emulation::generate(engine, expected));
    instructions.extend(debug_registers::generate(engine, expected));
    instructions.extend(anti_tamper::generate(engine, expected));

    instructions.extend(hash(engine));

    instructions.extend(publish(engine));

    instructions.extend(delay(engine));

    forever(instructions)
}

pub fn program(engine: &mut Engine, key: u64, expected: u64) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();

    instructions.extend(unlock(engine));

    instructions.extend(correct(engine, key, expected));

    instructions
}

fn delay(engine: &mut Engine) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();

    instructions.extend(reserve(0x30));

    instructions.extend(import(engine, ImportDef::NtDelayExecution));
    // Alertable -> RCX
    instructions.extend(set_register(VMReg::Rcx, 0));
    // Interval -> RDX
    instructions.extend(compute_memory(
        VMReg::Rsp,
        VMReg::None,
        1,
        0x20,
        VMSeg::None,
    ));
    instructions.extend(store_register(VMReg::Rdx));
    // Interval -> [RSP + ...]
    instructions.extend(store_immediate(
        VMReg::Rsp,
        VMReg::None,
        1,
        0x20,
        (-10000i64) as u64,
    ));
    // NtDelayExecution
    instructions.extend(invoke(VMReg::Rax));

    instructions.extend(release(0x30));

    instructions
}

fn publish(engine: &mut Engine) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();

    // Tick the current timestamp into RAX and write it as the freshness stamp:
    instructions.extend(timestamp());
    instructions.extend(mask(None, !((1u64 << TICK) - 1)));
    instructions.extend(store_register(VMReg::Rax));

    instructions.extend(load_register(VMReg::Rax));
    instructions.extend(store_data_at(engine, DataDef::VmServiceBox, 0));

    // Derive the keystream from the tick so the stored value is time-locked:
    instructions.extend(load_register(VMReg::Rax));
    instructions.extend(load_data(
        engine,
        DataDef::VmKeyInitializer,
        VMWidth::Lower64,
    ));
    instructions.extend(xor(None, None));
    instructions.extend(register_lcg(engine, None));
    instructions.extend(store_register(VMReg::Rcx));

    // Store the fingerprint XORed with the keystream:
    instructions.extend(load_register(VMReg::Vp0));
    instructions.extend(load_register(VMReg::Rcx));
    instructions.extend(xor(None, None));
    instructions.extend(store_data_at(engine, DataDef::VmServiceBox, 8));

    instructions
}

fn unlock(engine: &mut Engine) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();

    // Load the value published by the service:
    instructions.extend(load_data_at(
        engine,
        DataDef::VmServiceBox,
        0,
        VMWidth::Lower64,
    ));
    instructions.extend(store_register(VMReg::Rax));

    // Derive the keystream from the stored tick:
    instructions.extend(load_register(VMReg::Rax));
    instructions.extend(load_data(
        engine,
        DataDef::VmKeyInitializer,
        VMWidth::Lower64,
    ));
    instructions.extend(xor(None, None));
    instructions.extend(register_lcg(engine, None));
    instructions.extend(store_register(VMReg::Rcx));

    // Recover the fingerprint into Vp0:
    instructions.extend(load_data_at(
        engine,
        DataDef::VmServiceBox,
        8,
        VMWidth::Lower64,
    ));
    instructions.extend(load_register(VMReg::Rcx));
    instructions.extend(xor(None, None));
    instructions.extend(store_register(VMReg::Vp0));

    // Measure how many ticks old the fingerprint is:
    instructions.extend(timestamp());
    instructions.extend(mask(None, !((1u64 << TICK) - 1)));
    instructions.extend(load_register(VMReg::Rax));
    instructions.extend(sub(None, None));
    instructions.extend(store_register(VMReg::Rdx));

    // Store CF into RDX (CF=0 if the service is not stale)
    instructions.extend(immediate(STALE));
    instructions.extend(load_register(VMReg::Rdx));
    instructions.extend(sub(None, None));
    instructions.extend(discard());
    instructions.extend(flag(Flag::Carry));
    instructions.extend(store_register(VMReg::Rdx));

    // Flip the bits of RDX in-case it's non-zero to increase effectiveness:
    instructions.extend(immediate(0));
    instructions.extend(load_register(VMReg::Rdx));
    instructions.extend(sub(None, None));
    instructions.extend(store_register(VMReg::Rdx));

    // XOR Vp0 with Rdx to corrupt it in-case RDX was non-zero:
    instructions.extend(load_register(VMReg::Vp0));
    instructions.extend(load_register(VMReg::Rdx));
    instructions.extend(xor(None, None));
    instructions.extend(store_register(VMReg::Vp0));

    instructions
}

fn correct(engine: &mut Engine, key: u64, expected: u64) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();

    let correction = expected ^ key;

    // Offset of the block being decrypted (zero for the first block):
    instructions.extend(load_absolute(engine, DataDef::VmCodeStart, VMReg::R8));
    instructions.extend(sub(Some(VMReg::Vg0), Some(VMReg::R8)));
    instructions.extend(store_register(VMReg::Rdx));

    // First block chains off the initializer:
    instructions.extend(skip(
        engine,
        VMReg::Rdx,
        VMCondition::cmp(Flag::Zero, 0),
        |engine| immediate(engine.rt.keys.initializer),
    ));

    // Every other block chains off the previous block's trailing qword:
    instructions.extend(skip(
        engine,
        VMReg::Rdx,
        VMCondition::cmp(Flag::Zero, 1),
        |_| {
            load_memory(
                VMReg::Vg0,
                VMReg::None,
                1,
                -0xA,
                VMSeg::None,
                VMWidth::Lower64,
            )
        },
    ));

    instructions.extend(load_register(VMReg::Vp0));
    instructions.extend(xor(None, None));
    instructions.extend(immediate(correction));
    instructions.extend(xor(None, None));

    instructions.extend(register_lcg(engine, None));

    instructions.extend(store_register(VMReg::Vg0));

    instructions
}

fn hash(engine: &mut Engine) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();

    instructions.extend(load_absolute(engine, DataDef::VmCodeEnd, VMReg::Rax));
    instructions.extend(load_absolute(
        engine,
        DataDef::VmAttestationProgram,
        VMReg::Rcx,
    ));

    instructions.extend(sub(Some(VMReg::Rax), Some(VMReg::Rcx)));
    instructions.extend(immediate((crypt::HEADER_SIZE + crypt::TRAILER_SIZE) as u64));
    instructions.extend(sub(None, None));
    instructions.extend(store_register(VMReg::R9));

    instructions.extend(mask(Some(VMReg::R9), size_of::<u64>() as u64 - 1));
    instructions.extend(store_register(VMReg::R8));

    instructions.extend(sub(Some(VMReg::R9), Some(VMReg::R8)));
    instructions.extend(store_register(VMReg::R9));

    instructions.extend(set_register(VMReg::R10, 0));

    instructions.extend(foreach(
        engine,
        VMReg::Rax,
        Bound::Register(VMReg::R9),
        8,
        |engine| {
            let mut b = Vec::new();

            b.extend(load_register(VMReg::R10));
            b.extend(load_memory(
                VMReg::Rcx,
                VMReg::Rax,
                1,
                crypt::HEADER_SIZE as i32,
                VMSeg::None,
                VMWidth::Lower64,
            ));
            b.extend(xor(None, None));
            b.extend(register_lcg(engine, None));
            b.extend(store_register(VMReg::R10));

            b
        },
    ));

    instructions.extend(compute_memory(
        VMReg::Rcx,
        VMReg::R9,
        1,
        crypt::HEADER_SIZE as i32,
        VMSeg::None,
    ));
    instructions.extend(store_register(VMReg::Rcx));

    instructions.extend(foreach(
        engine,
        VMReg::Rax,
        Bound::Register(VMReg::R8),
        1,
        |engine| {
            let mut b = Vec::new();

            b.extend(load_register(VMReg::R10));
            b.extend(load_memory(
                VMReg::Rcx,
                VMReg::Rax,
                1,
                0,
                VMSeg::None,
                VMWidth::Lower8,
            ));
            b.extend(xor(None, None));
            b.extend(register_lcg(engine, None));
            b.extend(store_register(VMReg::R10));

            b
        },
    ));

    instructions.extend(load_register(VMReg::Vp0));
    instructions.extend(load_register(VMReg::R10));
    instructions.extend(xor(None, None));
    instructions.extend(store_register(VMReg::Vp0));

    instructions
}

fn register_lcg(engine: &mut Engine, register: Option<VMReg>) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();

    if let Some(register) = register {
        instructions.extend(load_register(register));
    }

    instructions.extend(load_data(
        engine,
        DataDef::VmKeyMultiplier,
        VMWidth::Lower64,
    ));
    instructions.extend(mul(None, None));

    instructions.extend(load_data(engine, DataDef::VmKeyAddend, VMWidth::Lower64));
    instructions.extend(add(None, None));

    instructions
}

fn apply_lcg(engine: &Engine, value: u64) -> u64 {
    value
        .wrapping_mul(engine.rt.keys.multiplier)
        .wrapping_add(engine.rt.keys.addend)
}

fn accumulate(
    engine: &mut Engine,
    accumulator: VMReg,
    source: Vec<Box<dyn Encode>>,
    value: u64,
    expected: &mut u64,
) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();

    instructions.extend(source);
    instructions.extend(load_register(accumulator));
    instructions.extend(xor(None, None));
    instructions.extend(register_lcg(engine, None));
    instructions.extend(store_register(accumulator));

    *expected = apply_lcg(engine, value ^ *expected);

    instructions
}

pub fn accumulate_immediate(
    engine: &mut Engine,
    accumulator: VMReg,
    source: Option<VMReg>,
    value: u64,
    expected: &mut u64,
) -> Vec<Box<dyn Encode>> {
    let source = match source {
        Some(register) => load_register(register),
        None => Vec::new(),
    };
    accumulate(engine, accumulator, source, value, expected)
}

pub fn accumulate_memory(
    engine: &mut Engine,
    accumulator: VMReg,
    base: VMReg,
    displacement: i32,
    width: VMWidth,
    value: u64,
    expected: &mut u64,
) -> Vec<Box<dyn Encode>> {
    let source = load_memory(base, VMReg::None, 1, displacement, VMSeg::None, width);
    accumulate(engine, accumulator, source, value, expected)
}

fn accumulate_byte(
    engine: &mut Engine,
    accumulator: VMReg,
    base: VMReg,
    displacement: i32,
    value: u64,
    expected: &mut u64,
) -> Vec<Box<dyn Encode>> {
    accumulate_memory(
        engine,
        accumulator,
        base,
        displacement,
        VMWidth::Lower8,
        value,
        expected,
    )
}

fn accumulate_prologue(
    engine: &mut Engine,
    accumulator: VMReg,
    base: VMReg,
    prologue: &[u8; 3],
    expected: &mut u64,
) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();

    for (offset, byte) in prologue.iter().enumerate() {
        instructions.extend(accumulate_byte(
            engine,
            accumulator,
            base,
            offset as i32,
            *byte as u64,
            expected,
        ));
    }
    instructions
}
