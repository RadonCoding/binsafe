use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::{i32, mem};

use crate::engine::Engine;
use crate::protections::virtualization::transforms::anti_debug::AntiDebug;
use crate::protections::Protection;
use exe::Buffer;
use exe::{PETranslation, PE, RVA};
use iced_x86::code_asm::CodeAssembler;
use iced_x86::Mnemonic;
use logger::info;
use runtime::vm::bytecode::{self};
use runtime::{
    runtime::{DataDef, FnDef},
    vm::bytecode::VMOp,
};

#[derive(Default)]
pub struct Virtualization {
    vblocks: HashMap<u64, usize>,
    failures: HashMap<Mnemonic, u32>,
    transforms: usize,
    dedupes: usize,
}

const VDISPATCH_SIZE: usize = 10;

impl Protection for Virtualization {
    fn initialize(&mut self, engine: &mut Engine) {
        let mut vtable = Vec::new();
        let mut vcode = Vec::new();

        let mut dedup = HashMap::new();

        let xrefs = &engine.xrefs;

        'outer: for block in &mut engine.blocks {
            if block.size < VDISPATCH_SIZE {
                continue;
            }

            let mut vblock = Vec::new();

            for instruction in &block.instructions {
                let bytecode = match bytecode::convert(&mut engine.rt.mapper, instruction) {
                    Some(virtualized) => virtualized,
                    None => {
                        let mnemonic = instruction.mnemonic();
                        *self.failures.entry(mnemonic).or_insert(0) += 1;
                        continue 'outer;
                    }
                };
                vblock.extend(bytecode);
            }

            if let Some(bytecode) = AntiDebug::transform(&mut engine.rt.mapper, xrefs, block) {
                vblock.splice(0..0, bytecode);
                self.transforms += 1;
            }

            vblock.push(engine.rt.mapper.index(VMOp::Invalid));

            let mut hasher = DefaultHasher::new();
            vblock.hash(&mut hasher);
            let hash = hasher.finish();

            let vcode_offset = if let Some(&offset) = dedup.get(&hash) {
                self.dedupes += 1;

                offset
            } else {
                let offset = vcode.len() as u32;
                vcode.extend_from_slice(&vblock);
                dedup.insert(hash, offset);
                offset
            };

            self.vblocks.insert(block.rva, vtable.len());

            vtable.extend_from_slice(&0u32.to_le_bytes());
            vtable.extend_from_slice(&vcode_offset.to_le_bytes());
        }

        if !vcode.is_empty() {
            engine.rt.define_data(DataDef::VmTable, &vtable);
            engine.rt.define_data(DataDef::VmCode, &vcode);
        }
    }

    fn apply(&self, engine: &mut Engine) {
        let ventry = engine.rt.lookup(engine.rt.func_labels[&FnDef::VmEntry]);

        let vtable_rva = engine.rt.lookup(engine.rt.data_labels[&DataDef::VmTable]);
        let vtable_offset = engine
            .pe
            .translate(PETranslation::Memory(RVA(vtable_rva as u32)))
            .unwrap();
        let vtable = unsafe { engine.pe.as_mut_ptr().add(vtable_offset) };

        for i in 0..engine.blocks.len() {
            let block = &engine.blocks[i];

            if !self.vblocks.contains_key(&block.rva) {
                continue;
            }

            let voffset = self.vblocks[&block.rva];
            let vindex = (voffset / 8) as i32;

            let mut asm = CodeAssembler::new(engine.bitness).unwrap();
            asm.push(vindex).unwrap();
            asm.call(ventry).unwrap();

            let dispatch = asm.assemble(block.rva).unwrap();

            assert!(dispatch.len() <= VDISPATCH_SIZE);

            unsafe {
                let displ = (block.size - dispatch.len()) as u32;
                vtable
                    .add(voffset)
                    .copy_from(displ.to_le_bytes().as_ptr(), mem::size_of::<u32>());
            }

            engine.replace(i, &dispatch);
        }

        let total = engine.blocks.len();
        let virtualized = self.vblocks.len();
        let percentage = (virtualized as f64 / total.max(1) as f64) * 100.0;

        let mut output = format!(
            "VIRTUALIZED: {}/{} blocks ({:.2}%) [transforms: {}] [dedupes: {}]",
            virtualized, total, percentage, self.transforms, self.dedupes
        );

        if !self.failures.is_empty() {
            let mut sorted = self.failures.iter().collect::<Vec<_>>();
            sorted.sort_by(|a, b| b.1.cmp(a.1));

            let top = sorted
                .iter()
                .take(10)
                .map(|(m, n)| format!("{:?}={}", m, n).to_lowercase())
                .collect::<Vec<String>>()
                .join(", ");
            output.push(' ');
            output.push_str(&format!("(most failures: {})", top));
        }

        info!("{}", output);
    }
}
