use std::collections::HashMap;
#[cfg(debug_assertions)]
use std::collections::HashSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::{i32, mem};

use crate::engine::Engine;
use crate::protections::Protection;
use exe::Buffer;
use exe::{PE, RVA};
use iced_x86::code_asm::CodeAssembler;
use logger::{debug, info};
use rand::Rng;
use runtime::runtime::{DataDef, FnDef};
use runtime::vm::{bytecode, permute};

mod attestation;
pub mod crypt;

#[derive(Default)]
pub struct Virtualization {
    vblocks: HashMap<u32, usize>,
    duplicates: usize,
}

// PUSH imm32 + CALL rel32
const DISPATCH_SIZE: usize = 10;

impl Protection for Virtualization {
    fn initialize(&mut self, engine: &mut Engine) {
        let mut vtable = Vec::new();
        let mut vcode = Vec::new();

        let mut dedup = HashMap::new();

        #[cfg(debug_assertions)]
        let mut logged = HashSet::new();

        let mut rng = rand::thread_rng();
        let key_seed = rng.gen::<u64>();
        let key_mul = rng.gen::<u64>();
        let key_add = rng.gen::<u64>();
        let key_att = rng.gen::<u64>();

        let mut attestation =
            bytecode::assemble(&mut engine.rt.mapper, &mut attestation::generate(key_att));

        crypt::encrypt(&mut attestation, key_seed, key_mul, key_add, 0, &mut rng);

        vcode.extend_from_slice(&attestation);

        'outer: for block in &mut engine.blocks {
            if block.size < DISPATCH_SIZE {
                continue;
            }

            let lifted = match bytecode::lift(&block.instructions) {
                Some(operations) if !operations.is_empty() => operations,
                _ => continue 'outer,
            };

            #[cfg(debug_assertions)]
            let before = lifted
                .iter()
                .map(|operation| format!("    {}", operation))
                .collect::<Vec<String>>()
                .join("\n");

            let mut operations = permute::permute(lifted);

            #[cfg(debug_assertions)]
            {
                let mut log = false;

                for instruction in &block.instructions {
                    if logged.insert(instruction.code()) {
                        log = true;
                    }
                }

                if log {
                    let instructions = block
                        .instructions
                        .iter()
                        .map(|instruction| format!("    {}", instruction))
                        .collect::<Vec<String>>()
                        .join("\n");
                    let after = operations
                        .iter()
                        .map(|operation| format!("    {}", operation))
                        .collect::<Vec<String>>()
                        .join("\n");
                    debug!(
                        "VIRTUALIZED @ 0x{:08X}:\n  BEFORE:\n{}\n  LIFTED:\n{}\n  PERMUTED:\n{}",
                        block.rva, instructions, before, after
                    );
                }
            }

            let mut vblock = bytecode::assemble(&mut engine.rt.mapper, &mut operations);

            let mut hasher = DefaultHasher::new();
            vblock.hash(&mut hasher);
            let hash = hasher.finish();

            // Check if the block already exists to avoid duplication
            let vcode_offset = if dedup.contains_key(&hash) {
                self.duplicates += 1;

                dedup[&hash]
            } else {
                let vcode_key = u64::from_le_bytes(vcode[vcode.len() - 8..].try_into().unwrap());

                crypt::encrypt(&mut vblock, vcode_key, key_mul, key_add, key_att, &mut rng);

                let vcode_offset = TryInto::<u32>::try_into(vcode.len()).unwrap();
                vcode.extend_from_slice(&vblock);

                dedup.insert(hash, vcode_offset);

                vcode_offset
            };

            // Store the offset of this VM-block's VM-table entry
            let vtable_offset = vtable.len();
            self.vblocks.insert(block.rva, vtable_offset);

            // Store the placeholder for stub displacement and offset in the linear VM-code
            vtable.extend_from_slice(&0u32.to_le_bytes());
            vtable.extend_from_slice(&vcode_offset.to_le_bytes());
        }

        engine.rt.define_data_bytes(DataDef::VmTable, &vtable);
        engine.rt.define_data_bytes(DataDef::VmCode, &vcode);

        engine.rt.define_data_qword(DataDef::VmKeySeed, key_seed);
        engine.rt.define_data_qword(DataDef::VmKeyMul, key_mul);
        engine.rt.define_data_qword(DataDef::VmKeyAdd, key_add);
    }

    fn apply(&self, engine: &mut Engine) {
        let ventry_rva = engine.rt.lookup(engine.rt.func_labels[&FnDef::VmEntry]);

        let vtable_rva = engine.rt.lookup(engine.rt.data_labels[&DataDef::VmTable]) as u32;
        let vtable_offset = engine.pe.translate(RVA(vtable_rva).into()).unwrap();
        let vtable = unsafe { engine.pe.as_ptr().add(vtable_offset) as *mut u8 };

        for i in 0..engine.blocks.len() {
            let block = &engine.blocks[i];

            if !self.vblocks.contains_key(&block.rva) {
                continue;
            }

            let vtable_offset = self.vblocks[&block.rva];
            // OR with 0x10000000 to force PUSH imm32, to ensure consistent size after encrypting
            let vtable_index = (vtable_offset / 8) as i32 | 0x10000000;

            let mut asm = CodeAssembler::new(engine.bitness).unwrap();

            asm.push(vtable_index).unwrap();
            asm.call(ventry_rva).unwrap();
            let dispatch1 = asm.assemble(block.rva as u64).unwrap();

            assert!(dispatch1.len() <= DISPATCH_SIZE);

            asm.reset();

            // Stub has to be assembled twice so that the runtime return address can be calculated
            let return_address = block.rva as i32 + dispatch1.len() as i32;

            asm.push(vtable_index ^ return_address).unwrap();
            asm.call(ventry_rva).unwrap();
            let dispatch2 = asm.assemble(block.rva as u64).unwrap();

            assert_eq!(dispatch1.len(), dispatch2.len());

            // Patch the stub displacement placeholder in the VM-table
            unsafe {
                let displacement = (block.size - dispatch2.len()) as u32;
                vtable
                    .add(vtable_offset)
                    .copy_from(displacement.to_le_bytes().as_ptr(), mem::size_of::<u32>());
            }

            engine.replace(i, &dispatch2);
        }

        let total = engine.blocks.len();
        let virtualized = self.vblocks.len();
        let percentage = (virtualized as f64 / total.max(1) as f64) * 100.0;

        info!(
            "VIRTUALIZED: {}/{} blocks ({:.2}%) [duplicates: {}]",
            virtualized, total, percentage, self.duplicates
        );
    }
}
