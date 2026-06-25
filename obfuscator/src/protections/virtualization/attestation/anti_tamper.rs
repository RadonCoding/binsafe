use std::{convert::TryInto, i32};

use crate::engine::Engine;
use crate::protections::virtualization::attestation::*;
use exe::{Buffer, PE, RVA};
use rand::Rng;
use runtime::mapper::Mappable;
use runtime::runtime::{DataDef, FnDef};
use runtime::vm::bytecode::{VMReg, VMSeg, VMVec, VMWidth};
use runtime::vm::encoders::Encode;

const ACCUMULATOR: VMVec = VMVec::Ymm6;

pub fn generate(
    engine: &mut Engine,
    rng: &mut impl Rng,
    expected: &mut u64,
    mix: u32,
) -> Vec<Box<dyn Encode>> {
    let operation = rng.gen_range(0..3);

    let mut lane0 = 0;
    let mut lane1 = 0;

    for &function in FnDef::VARIANTS.iter() {
        let rva = engine.rt.lookup(engine.rt.function_labels[&function]) as u32;
        let size = engine.rt.size(engine.rt.function_labels[&function]) as usize;

        let offset = engine.pe.translate(RVA(rva).into()).unwrap();
        let bytes = engine.pe.read(offset, size).unwrap();

        let mut chunks = bytes.chunks_exact(size_of::<u128>());

        for chunk in &mut chunks {
            let lo = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
            let hi = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
            apply(operation, lo, &mut lane0);
            apply(operation, hi, &mut lane1);
        }

        for &byte in chunks.remainder() {
            apply(operation, byte as u64, &mut lane0);
        }
    }

    *expected = lane0 ^ lane1;

    let count = FnDef::VARIANTS.len();

    let functions = engine.rt.lookup(engine.rt.data_labels[&DataDef::Functions]) as i32;

    let mut instructions = Vec::<Box<dyn Encode>>::new();
    instructions.extend(set_vector(ACCUMULATOR, 0, 0));

    instructions.extend(foreach(VMReg::Rax, Bound::Immediate(count), 1, || {
        let mut outer = Vec::<Box<dyn Encode>>::new();

        outer.extend(absolute(VMReg::Rax, 8, functions, VMWidth::Lower32));
        outer.extend(reload_register(VMReg::Rcx));

        outer.extend(load(
            VMReg::VImage,
            VMReg::Rax,
            8,
            functions + 4,
            VMSeg::None,
            VMWidth::Lower32,
        ));
        outer.extend(reload_register(VMReg::Rdx));

        outer.extend(mask(Some(VMReg::Rdx), 15));
        outer.extend(reload_register(VMReg::R8));
        outer.extend(sub(Some(VMReg::Rdx), Some(VMReg::R8)));
        outer.extend(reload_register(VMReg::R9));

        outer.extend(foreach(VMReg::R10, Bound::Register(VMReg::R9), 16, || {
            let mut inner = Vec::<Box<dyn Encode>>::new();

            inner.extend(spill_vector(ACCUMULATOR, VMWidth::Lower128));
            inner.extend(load(
                VMReg::Rcx,
                VMReg::R10,
                1,
                0,
                VMSeg::None,
                VMWidth::Lower128,
            ));
            inner.push(create_vector(operation));
            inner.extend(reload_vector(ACCUMULATOR, VMWidth::Lower128));

            inner
        }));

        outer.extend(compute(VMReg::Rcx, VMReg::R10, 1, 0, VMSeg::None));
        outer.extend(reload_register(VMReg::Rdx));

        outer.extend(skip(
            engine,
            VMReg::R8,
            VMCondition::cmp(VMFlag::Zero, 1),
            |_| {
                foreach(VMReg::R9, Bound::Register(VMReg::R8), 1, || {
                    let mut inner = Vec::<Box<dyn Encode>>::new();

                    inner.extend(spill_vector(ACCUMULATOR, VMWidth::Lower64));
                    inner.extend(load(
                        VMReg::Rdx,
                        VMReg::R9,
                        1,
                        0,
                        VMSeg::None,
                        VMWidth::Lower8,
                    ));
                    inner.extend(create(operation));
                    inner.extend(reload_vector(ACCUMULATOR, VMWidth::Lower64));

                    inner
                })
            },
        ));

        outer
    }));

    instructions.extend(spill_vector(ACCUMULATOR, VMWidth::Lower128));
    instructions.extend(xor(None, None));
    instructions.extend(spill_register(VMReg::Vt0));
    instructions.extend(create(mix));
    instructions.extend(reload_register(VMReg::Vp1));

    instructions
}
