use std::i32;

use crate::engine::Engine;
use crate::protections::virtualization::{crypt, language::*};
use rand::Rng;
use runtime::runtime::DataDef;
use runtime::vm::bytecode::{Flag, VMCondition, VMPrecision, VMReg, VMSeg, VMWidth};
use runtime::vm::encoders::vector_add::VectorAdd;
use runtime::vm::encoders::vector_sub::VectorSub;
use runtime::vm::encoders::vector_xor::VectorXor;
use runtime::vm::encoders::Encode;

mod anti_debug;
mod anti_tamper;
#[cfg(debug_assertions)]
mod debug;

// Masks lower 34 bits of timestamp, creating a ~5s window on a 3.5 GHz CPU
const WINDOW: u64 = 0x22;

const MINIMUM_CYCLES: u64 = 1_000_000;
const MAXIMUM_CYCLES: u64 = 100_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Add,
    Sub,
    Xor,
}

impl Operation {
    pub fn random(rng: &mut impl Rng) -> Self {
        match rng.gen_range(0..3) {
            0 => Operation::Add,
            1 => Operation::Sub,
            _ => Operation::Xor,
        }
    }
}

pub fn generate(engine: &mut Engine, key: u64) -> Vec<Vec<Box<dyn Encode>>> {
    let mut rng = rand::thread_rng();

    let mut blocks = Vec::<Vec<Box<dyn Encode>>>::new();

    let mut block = Vec::<Box<dyn Encode>>::new();

    let mut vp0 = 0;
    let mut vp1 = 0;

    block.extend(timestamp());
    block.extend(mask(None, !((1u64 << WINDOW) - 1)));
    block.extend(lcg(engine, None));
    block.extend(store_register(VMReg::Vt0));

    block.extend(sub(Some(VMReg::Vt0), Some(VMReg::Vt1)));

    block.extend(store_register(VMReg::Rax));

    block.extend(skip(
        engine,
        VMReg::Rax,
        VMCondition::cmp(Flag::Zero, 1),
        |engine| {
            let mut b = Vec::<Box<dyn Encode>>::new();

            b.extend(timestamp());

            b.extend(anti_debug::generate(engine, &mut rng, &mut vp0));
            b.extend(anti_tamper::generate(engine, &mut rng, &mut vp1));

            b.extend(store_register(VMReg::Rax));

            b.extend(timestamp());

            b.extend(sub(Some(VMReg::Rax), None));

            b.extend(store_register(VMReg::Rax));

            b.extend(load_register(VMReg::Rax));
            b.extend(immediate(MINIMUM_CYCLES));
            b.extend(sub(None, None));
            b.extend(discard());

            b.extend(flag(Flag::Carry));

            b.extend(store_register(VMReg::Rcx));

            b.extend(accumulate_immediate(
                &mut rng,
                VMReg::Vp0,
                Some(VMReg::Rcx),
                0,
                &mut vp0,
            ));
            b.extend(accumulate_immediate(
                &mut rng,
                VMReg::Vp1,
                Some(VMReg::Rcx),
                0,
                &mut vp1,
            ));

            b.extend(immediate(MAXIMUM_CYCLES));
            b.extend(load_register(VMReg::Rax));
            b.extend(sub(None, None));
            b.extend(discard());

            b.extend(flag(Flag::Carry));

            b.extend(store_register(VMReg::Rcx));

            b.extend(accumulate_immediate(
                &mut rng,
                VMReg::Vp0,
                Some(VMReg::Rcx),
                0,
                &mut vp0,
            ));
            b.extend(accumulate_immediate(
                &mut rng,
                VMReg::Vp1,
                Some(VMReg::Rcx),
                0,
                &mut vp1,
            ));

            b.extend(xor(Some(VMReg::Vp0), Some(VMReg::Vt0)));
            b.extend(store_register(VMReg::Vp0));
            b.extend(xor(Some(VMReg::Vp1), Some(VMReg::Vt0)));
            b.extend(store_register(VMReg::Vp1));

            b.extend(copy(VMReg::Vt0, VMReg::Vt1));

            b
        },
    ));

    block.extend(correct(engine, &mut rng, key, vp0, vp1));

    blocks.push(block);

    blocks
}

fn correct(
    engine: &mut Engine,
    rng: &mut impl Rng,
    key: u64,
    vp0: u64,
    vp1: u64,
) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();

    instructions.extend(load_absolute(engine, DataDef::VmAttestation, VMReg::Rax));
    instructions.extend(load_absolute(engine, DataDef::VmCode, VMReg::Rcx));

    instructions.extend(sub(Some(VMReg::Vg0), Some(VMReg::Rax)));
    instructions.extend(store_register(VMReg::Rdx));

    instructions.extend(skip(
        engine,
        VMReg::Rdx,
        VMCondition::cmp(Flag::Zero, 0),
        |_| {
            let mut b = Vec::new();

            b.extend(sub(Some(VMReg::Rax), Some(VMReg::Rcx)));
            b.extend(immediate((crypt::HEADER_SIZE + crypt::TRAILER_SIZE) as u64));
            b.extend(sub(None, None));
            b.extend(store_register(VMReg::R9));

            b.extend(set_register(VMReg::R10, 0));

            b.extend(foreach(VMReg::R8, Bound::Register(VMReg::R9), 8, || {
                let mut outer = Vec::new();

                outer.extend(load_register(VMReg::R10));
                outer.extend(load_memory(
                    VMReg::Rcx,
                    VMReg::R8,
                    1,
                    crypt::HEADER_SIZE as i32,
                    VMSeg::None,
                    VMWidth::Lower64,
                ));
                outer.extend(xor(None, None));
                outer.extend(store_register(VMReg::R10));

                outer
            }));

            b.extend(load_register(VMReg::R10));

            b
        },
    ));

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

    let operation = Operation::random(rng);
    let combined = combine_operation(operation, vp0, vp1);
    let correction = combined ^ key;

    instructions.extend(xor(Some(VMReg::Vp0), Some(VMReg::Vt0)));
    instructions.extend(xor(Some(VMReg::Vp1), Some(VMReg::Vt0)));
    instructions.extend(register_operation(operation));
    instructions.extend(immediate(correction));
    instructions.extend(xor(None, None));

    instructions.extend(xor(None, None));

    instructions.extend(store_register(VMReg::Vg0));

    instructions
}

fn lcg(engine: &mut Engine, register: Option<VMReg>) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();

    instructions.extend(load_data(
        engine,
        DataDef::VmKeyMultiplier,
        VMWidth::Lower64,
    ));
    instructions.extend(mul(register, None));

    instructions.extend(load_data(engine, DataDef::VmKeyAddend, VMWidth::Lower64));
    instructions.extend(add(register, None));

    instructions
}

fn combine_operation(operation: Operation, a: u64, b: u64) -> u64 {
    let mut result = a;
    apply_operation(operation, b, &mut result);
    result
}

fn apply_operation(operation: Operation, value: u64, expected: &mut u64) {
    match operation {
        Operation::Add => *expected = expected.wrapping_add(value),
        Operation::Sub => *expected = expected.wrapping_sub(value),
        Operation::Xor => *expected ^= value,
    }
}

fn register_operation(operation: Operation) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();

    match operation {
        Operation::Add => instructions.extend(add(None, None)),
        Operation::Sub => instructions.extend(sub(None, None)),
        Operation::Xor => instructions.extend(xor(None, None)),
    }

    instructions
}

fn vector_operation(operation: Operation) -> Box<dyn Encode> {
    match operation {
        Operation::Add => Box::new(VectorAdd {
            width: VMWidth::Lower128,
            stride: VMWidth::Lower64,
            precision: VMPrecision::Integer,
        }),
        Operation::Sub => Box::new(VectorSub {
            width: VMWidth::Lower128,
            stride: VMWidth::Lower64,
            precision: VMPrecision::Integer,
        }),
        Operation::Xor => Box::new(VectorXor {
            width: VMWidth::Lower128,
        }),
    }
}

fn accumulate<R: Rng>(
    rng: &mut R,
    accumulator: VMReg,
    source: Vec<Box<dyn Encode>>,
    value: u64,
    expected: &mut u64,
) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();

    let operation = Operation::random(rng);

    let mix = rng.gen::<u64>();

    instructions.extend(load_register(accumulator));
    instructions.extend(source);
    instructions.extend(immediate(mix));
    instructions.extend(xor(None, None));
    instructions.extend(register_operation(operation));
    instructions.extend(store_register(accumulator));

    apply_operation(operation, value ^ mix, expected);

    instructions
}

pub fn accumulate_immediate<R: Rng>(
    rng: &mut R,
    accumulator: VMReg,
    source: Option<VMReg>,
    value: u64,
    expected: &mut u64,
) -> Vec<Box<dyn Encode>> {
    let source = match source {
        Some(register) => load_register(register),
        None => Vec::new(),
    };
    accumulate(rng, accumulator, source, value, expected)
}

pub fn accumulate_memory<R: Rng>(
    rng: &mut R,
    accumulator: VMReg,
    base: VMReg,
    displacement: i32,
    width: VMWidth,
    value: u64,
    expected: &mut u64,
) -> Vec<Box<dyn Encode>> {
    let source = load_memory(base, VMReg::None, 1, displacement, VMSeg::None, width);
    accumulate(rng, accumulator, source, value, expected)
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
