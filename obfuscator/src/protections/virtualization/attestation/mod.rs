use std::i32;

use crate::engine::Engine;
use crate::protections::virtualization::language::*;
use rand::Rng;
use runtime::runtime::DataDef;
use runtime::vm::bytecode::{VMCondition, VMFlag, VMPrecision, VMReg, VMSeg, VMWidth};
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

    pub fn invert(self) -> Self {
        match self {
            Operation::Add => Operation::Sub,
            Operation::Sub => Operation::Add,
            Operation::Xor => Operation::Xor,
        }
    }
}

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

    block.extend(reload_register(VMReg::Vt0));

    block.extend(sub(Some(VMReg::Vt0), Some(VMReg::Vt1)));
    block.extend(reload_register(VMReg::Rax));

    let mut vp0 = 0;
    let mut vp1 = 0;

    let mix0 = Operation::random(&mut rng);
    let mix1 = Operation::random(&mut rng);

    block.extend(skip(
        engine,
        VMReg::Rax,
        VMCondition::cmp(VMFlag::Zero, 1),
        |engine| {
            let mut b = Vec::<Box<dyn Encode>>::new();

            b.extend(anti_debug::generate(engine, &mut rng, &mut vp0, mix0));
            b.extend(anti_tamper::generate(engine, &mut rng, &mut vp1, mix1));

            b.extend(copy(VMReg::Vt0, VMReg::Vt1));

            b
        },
    ));

    block.extend(correct(&mut rng, key, vp0, mix0, vp1, mix1));

    blocks.push(block);

    blocks
}

fn correct(
    rng: &mut impl Rng,
    key: u64,
    vp0: u64,
    mix0: Operation,
    vp1: u64,
    mix1: Operation,
) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();

    instructions.extend(load(
        VMReg::Vg0,
        VMReg::None,
        1,
        -0xA,
        VMSeg::None,
        VMWidth::Lower64,
    ));

    let operation = Operation::random(rng);
    let combined = combine_operation(operation, vp0, vp1);
    let correction = combined ^ key;

    instructions.extend(spill_register(VMReg::Vp0));
    instructions.extend(spill_register(VMReg::Vt0));
    instructions.extend(register_operation(mix0.invert()));
    instructions.extend(spill_register(VMReg::Vp1));
    instructions.extend(spill_register(VMReg::Vt0));
    instructions.extend(register_operation(mix1.invert()));
    instructions.extend(register_operation(operation));
    instructions.extend(immediate(correction));
    instructions.extend(xor(None, None));

    instructions.extend(xor(None, None));

    instructions.extend(reload_register(VMReg::Vg0));

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
    source: VMReg,
    value: u64,
    expected: &mut u64,
) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();

    let operation = Operation::random(rng);

    instructions.extend(spill_register(accumulator));
    instructions.extend(spill_register(source));
    instructions.extend(register_operation(operation));
    instructions.extend(reload_register(accumulator));

    apply_operation(operation, value, expected);

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

    let operation = Operation::random(rng);

    instructions.extend(spill_register(accumulator));
    instructions.extend(load(base, VMReg::None, 1, displacement, VMSeg::None, width));
    instructions.extend(register_operation(operation));
    instructions.extend(reload_register(accumulator));

    apply_operation(operation, value, expected);

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
