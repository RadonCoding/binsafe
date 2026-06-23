use std::rc::Rc;
use std::{convert::TryInto, i32};

use crate::engine::Engine;
use crate::protections::virtualization::attestation::*;
use exe::{Buffer, PE, RVA};
use rand::Rng;
use runtime::mapper::Mappable;
use runtime::runtime::{DataDef, FnDef};
use runtime::vm::bytecode::{VMReg, VMWidth};
use runtime::vm::encoders::Encode;

const ACCUMULATOR: VMReg = VMReg::R13;

pub fn generate(
    engine: &mut Engine,
    rng: &mut impl Rng,
    expected: &mut u64,
) -> Vec<Rc<dyn Encode>> {
    let operation = rng.gen_range(0..3);

    for &function in FnDef::VARIANTS.iter() {
        let rva = engine.rt.lookup(engine.rt.function_labels[&function]) as u32;
        let size = engine.rt.size(engine.rt.function_labels[&function]) as usize;

        let offset = engine.pe.translate(RVA(rva).into()).unwrap();
        let bytes = engine.pe.read(offset, size).unwrap();

        let mut chunks = bytes.chunks_exact(size_of::<u64>());

        for chunk in &mut chunks {
            let value = u64::from_le_bytes(chunk.try_into().unwrap());
            apply(operation, value, expected);
        }

        for &byte in chunks.remainder() {
            apply(operation, byte as u64, expected);
        }
    }

    let count = FnDef::VARIANTS.len();

    skip(
        engine,
        VMReg::Vp1,
        VMCondition::cmp(VMFlag::Zero, 0),
        |engine| {
            let functions = engine.rt.lookup(engine.rt.data_labels[&DataDef::Functions]) as i32;

            let mut b = Vec::<Rc<dyn Encode>>::new();

            b.extend(set(ACCUMULATOR, 0));

            b.extend(foreach(VMReg::Rax, Bound::Immediate(count), 1, || {
                let mut outer = Vec::<Rc<dyn Encode>>::new();

                outer.extend(absolute(VMReg::Rax, 8, functions, VMWidth::Lower32));
                outer.extend(save(VMReg::Rbx));

                outer.extend(load(
                    VMReg::VImage,
                    VMReg::Rax,
                    8,
                    functions + 4,
                    VMWidth::Lower32,
                ));
                outer.extend(save(VMReg::Rcx));

                outer.extend(mask(VMReg::Rcx, 7));
                outer.extend(save(VMReg::Rdx));
                outer.extend(sub(VMReg::Rcx, VMReg::Rdx));
                outer.extend(save(VMReg::R8));

                outer.extend(foreach(VMReg::R9, Bound::Register(VMReg::R8), 8, || {
                    let mut inner = Vec::<Rc<dyn Encode>>::new();
                    inner.extend(load(VMReg::Rbx, VMReg::R9, 1, 0, VMWidth::Lower64));
                    inner.extend(create(ACCUMULATOR, operation));
                    inner
                }));

                outer.extend(compute(VMReg::Rbx, VMReg::R9, 1, 0));
                outer.extend(save(VMReg::R10));

                outer.extend(skip(
                    engine,
                    VMReg::Rdx,
                    VMCondition::cmp(VMFlag::Zero, 1),
                    |_| {
                        foreach(VMReg::R11, Bound::Register(VMReg::Rdx), 1, || {
                            let mut inner = Vec::<Rc<dyn Encode>>::new();
                            inner.extend(load(VMReg::R10, VMReg::R11, 1, 0, VMWidth::Lower8));
                            inner.extend(create(ACCUMULATOR, operation));
                            inner
                        })
                    },
                ));

                outer
            }));

            b.extend(copy(ACCUMULATOR, VMReg::Vp1));

            b
        },
    )
}
