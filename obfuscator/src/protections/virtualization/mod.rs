pub mod transforms;

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::{i32, mem};

use crate::engine::Engine;
use crate::protections::virtualization::transforms::anti_debug::AntiDebug;
use crate::protections::Protection;
use exe::Buffer;
use exe::{PETranslation, PE, RVA};
use iced_x86::code_asm::CodeAssembler;
use logger::info;
use rand::Rng;
use runtime::runtime::{DataDef, FnDef};
use runtime::vm::bytecode::{self};

#[derive(Default)]
pub struct Virtualization {
    vblocks: HashMap<u32, usize>,
    transforms: usize,
    dedupes: usize,
}

const VDISPATCH_SIZE: usize = 10;

const NTQIP_SIGNATURE: u8 = 0x4C;

impl Protection for Virtualization {
    fn initialize(&mut self, engine: &mut Engine) {
        let mut vtable = Vec::new();
        let mut vcode = Vec::new();

        let mut dedup = HashMap::new();

        let mut rng = rand::thread_rng();
        let key_seed = rng.gen::<u64>();
        let key_mul = rng.gen::<u64>();
        let key_add = rng.gen::<u64>();

        'outer: for block in &mut engine.blocks {
            if block.size < VDISPATCH_SIZE {
                continue;
            }

            let mut vblock = match bytecode::convert(&mut engine.rt.mapper, &block.instructions) {
                Some(virtualized) => virtualized,
                None => continue 'outer,
            };

            if let Some(bytecode) = AntiDebug::transform(&mut engine.rt.mapper, block) {
                vblock.splice(0..0, bytecode);
                self.transforms += 1;
            }

            let mut vcode_key = if vcode.is_empty() {
                key_seed
            } else {
                u32::from_le_bytes(vcode[vcode.len() - 4..].try_into().unwrap()) as u64
            };

            for byte in &mut vblock {
                *byte ^= vcode_key as u8;
                vcode_key ^= (*byte ^ NTQIP_SIGNATURE) as u64;
                vcode_key = vcode_key.wrapping_mul(key_mul).wrapping_add(key_add);
            }

            let length = TryInto::<u16>::try_into(vblock.len()).unwrap();
            vblock.splice(0..0, length.to_le_bytes());

            vblock.push(0);

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

            let vtable_offset = vtable.len();

            self.vblocks.insert(block.rva, vtable_offset);

            let vtable_key = if vtable_offset == 0 {
                key_seed as u32
            } else {
                u32::from_le_bytes(vtable[vtable_offset - 4..vtable_offset].try_into().unwrap())
            };

            let encrypted_vcode_offset = vcode_offset ^ vtable_key;

            vtable.extend_from_slice(&0u32.to_le_bytes());
            vtable.extend_from_slice(&encrypted_vcode_offset.to_le_bytes());
        }

        if !vcode.is_empty() {
            engine.rt.define_data_bytes(DataDef::VmTable, &vtable);
            engine.rt.define_data_bytes(DataDef::VmCode, &vcode);

            engine.rt.define_data_qword(DataDef::VmKeySeed, key_seed);
            engine.rt.define_data_qword(DataDef::VmKeyMul, key_mul);
            engine.rt.define_data_qword(DataDef::VmKeyAdd, key_add);
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

            let vtable_offset = self.vblocks[&block.rva];
            let vtable_index = (vtable_offset / 8) as i32 | 0x10000000;

            let mut asm = CodeAssembler::new(engine.bitness).unwrap();
            asm.push(vtable_index).unwrap();
            asm.call(ventry).unwrap();
            let dispatch1 = asm.assemble(block.rva as u64).unwrap();

            assert!(dispatch1.len() <= VDISPATCH_SIZE);

            asm.reset();

            let ret = block.rva as i32 + dispatch1.len() as i32;

            asm.push(vtable_index ^ ret).unwrap();
            asm.call(ventry).unwrap();
            let dispatch2 = asm.assemble(block.rva as u64).unwrap();

            assert_eq!(dispatch1.len(), dispatch2.len());

            unsafe {
                let displ = (block.size - dispatch2.len()) as u32;
                vtable
                    .add(vtable_offset)
                    .copy_from(displ.to_le_bytes().as_ptr(), mem::size_of::<u32>());
            }

            engine.replace(i, &dispatch2);
        }

        let total = engine.blocks.len();
        let virtualized = self.vblocks.len();
        let percentage = (virtualized as f64 / total.max(1) as f64) * 100.0;

        info!(
            "VIRTUALIZED: {}/{} blocks ({:.2}%) [transforms: {}] [dedupes: {}]",
            virtualized, total, percentage, self.transforms, self.dedupes
        );
    }
}
