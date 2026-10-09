use std::convert::TryInto;

use crate::engine::Engine;
use crate::protections::virtualization::attestation::*;
use exe::{Buffer, PE, RVA};
use runtime::mapper::Mappable;
use runtime::runtime::{DataDef, FnDef};
use runtime::vm::bytecode::{VMReg, VMSeg, VMWidth};
use runtime::vm::encoders::Encode;

pub fn generate(engine: &mut Engine, expected: &mut u64) -> Vec<Box<dyn Encode>> {
    let mut hash = *expected;

    for &function in FnDef::VARIANTS.iter() {
        let rva = engine.rt.lookup(engine.rt.function_labels[&function]) as u32;
        let size = engine.rt.size(engine.rt.function_labels[&function]) as usize;

        let offset = engine.pe.translate(RVA(rva).into()).unwrap();
        let bytes = engine.pe.read(offset, size).unwrap();

        let mut chunks = bytes.chunks_exact(size_of::<u64>());

        for chunk in &mut chunks {
            let word = u64::from_le_bytes(chunk.try_into().unwrap());
            hash = apply_lcg(engine, hash ^ word);
        }

        for &byte in chunks.remainder() {
            hash = apply_lcg(engine, hash ^ byte as u64);
        }
    }

    *expected = hash;

    let count = FnDef::VARIANTS.len();

    let functions = engine.rt.lookup(engine.rt.data_labels[&DataDef::Functions]) as i32;

    let mut instructions = Vec::<Box<dyn Encode>>::new();

    instructions.extend(foreach(
        engine,
        VMReg::Rax,
        Bound::Immediate(count),
        1,
        |engine| {
            let mut outer = Vec::<Box<dyn Encode>>::new();

            outer.extend(load_memory(
                VMReg::VImage,
                VMReg::Rax,
                8,
                functions,
                VMSeg::None,
                VMWidth::Lower64,
            ));
            outer.extend(store_register(VMReg::Rcx));

            outer.extend(load_register(VMReg::Rcx));
            outer.extend(immediate(0x20));
            outer.extend(shr(None, None));
            outer.extend(store_register(VMReg::Rdx));

            outer.extend(mask(Some(VMReg::Rcx), 0xFFFF_FFFF));
            outer.extend(load_register(VMReg::VImage));
            outer.extend(add(None, None));
            outer.extend(store_register(VMReg::Rcx));

            outer.extend(mask(Some(VMReg::Rdx), 7));
            outer.extend(store_register(VMReg::R8));
            outer.extend(sub(Some(VMReg::Rdx), Some(VMReg::R8)));
            outer.extend(store_register(VMReg::R9));

            outer.extend(foreach(
                engine,
                VMReg::R10,
                Bound::Register(VMReg::R9),
                8,
                |engine| {
                    let mut inner = Vec::<Box<dyn Encode>>::new();

                    inner.extend(load_register(VMReg::Vp0));
                    inner.extend(load_memory(
                        VMReg::Rcx,
                        VMReg::R10,
                        1,
                        0,
                        VMSeg::None,
                        VMWidth::Lower64,
                    ));
                    inner.extend(xor(None, None));
                    inner.extend(register_lcg(engine, None));
                    inner.extend(store_register(VMReg::Vp0));

                    inner
                },
            ));

            outer.extend(compute_memory(VMReg::Rcx, VMReg::R9, 1, 0, VMSeg::None));
            outer.extend(store_register(VMReg::Rdx));

            outer.extend(foreach(
                engine,
                VMReg::R9,
                Bound::Register(VMReg::R8),
                1,
                |engine| {
                    let mut inner = Vec::<Box<dyn Encode>>::new();

                    inner.extend(load_register(VMReg::Vp0));
                    inner.extend(load_memory(
                        VMReg::Rdx,
                        VMReg::R9,
                        1,
                        0,
                        VMSeg::None,
                        VMWidth::Lower8,
                    ));
                    inner.extend(xor(None, None));
                    inner.extend(register_lcg(engine, None));
                    inner.extend(store_register(VMReg::Vp0));

                    inner
                },
            ));

            outer
        },
    ));

    instructions
}
