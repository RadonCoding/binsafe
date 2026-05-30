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
use logger::info;
use rand::Rng;
use runtime::runtime::{DataDef, FnDef};
use runtime::vm::{bytecode, permute};

mod attestation;
pub mod crypt;

struct Keys {
    seed: u64,
    mul: u64,
    add: u64,
    att: u64,
}

impl Default for Keys {
    fn default() -> Self {
        let mut rng = rand::thread_rng();

        Self {
            seed: rng.gen::<u64>(),
            mul: rng.gen::<u64>(),
            add: rng.gen::<u64>(),
            att: rng.gen::<u64>(),
        }
    }
}

#[derive(Default)]
pub struct Virtualization {
    keys: Keys,
    vblocks: HashMap<u32, usize>,
    duplicates: usize,
}

// PUSH imm32 + CALL rel32
const DISPATCH_SIZE: usize = 10;

#[cfg(debug_assertions)]
fn format_operations_with(
    before: &[String],
    after: &[Box<dyn runtime::vm::encoders::Encode>],
) -> String {
    let mut positions = HashMap::<&str, std::collections::VecDeque<usize>>::new();
    for (i, line) in before.iter().enumerate() {
        positions
            .entry(line.as_str())
            .or_insert_with(std::collections::VecDeque::new)
            .push_back(i);
    }

    after
        .iter()
        .map(|operation| {
            let key = format!("{}", operation);
            match positions
                .get_mut(key.as_str())
                .and_then(|queue| queue.pop_front())
            {
                Some(index) => format!("  {:>3}   {}", index, key),
                None => format!("    +   {}", key),
            }
        })
        .collect::<Vec<String>>()
        .join("\n")
}

impl Virtualization {
    fn attestation(&self, engine: &mut Engine) -> Vec<u8> {
        let blocks = attestation::generate(engine, self.keys.att);

        let mut vcode = Vec::new();

        #[cfg(debug_assertions)]
        let mut log = Vec::new();

        for (index, operations) in blocks.into_iter().enumerate() {
            #[cfg(debug_assertions)]
            let before = operations
                .iter()
                .map(|operation| format!("{}", operation))
                .collect::<Vec<String>>();

            let operations = permute::permute(operations);

            #[cfg(debug_assertions)]
            log.push(format!(
                "  BLOCK {}:\n{}",
                index,
                format_operations_with(&before, &operations)
            ));

            let mut vblock = bytecode::assemble(&mut engine.rt.mapper, &operations);

            let key = if vcode.is_empty() {
                self.keys.seed
            } else {
                u64::from_le_bytes(vcode[vcode.len() - 8..].try_into().unwrap())
            };

            crypt::encrypt(&mut vblock, key, self.keys.mul, self.keys.add, 0);

            vcode.extend_from_slice(&vblock);
        }

        #[cfg(debug_assertions)]
        {
            use logger::debug;

            debug!(
                "ATTESTATION @ 0x{:016X}:\n{}",
                self.keys.att,
                log.join("\n")
            );
        }

        vcode
    }
}

impl Protection for Virtualization {
    fn initialize(&mut self, engine: &mut Engine) {
        let mut vtable = Vec::new();
        let mut vcode = Vec::new();

        let mut dedup = HashMap::new();

        #[cfg(debug_assertions)]
        let mut logged = HashSet::new();

        vcode.extend_from_slice(&self.attestation(engine));

        'outer: for block in &mut engine.blocks {
            if block.size < DISPATCH_SIZE {
                continue;
            }

            let operations = match bytecode::lift(&block.instructions) {
                Some(ops) if !ops.is_empty() => ops,
                _ => continue 'outer,
            };

            let vblock = bytecode::assemble(&mut engine.rt.mapper, &operations);

            let mut hasher = DefaultHasher::new();
            vblock.hash(&mut hasher);
            let hash = hasher.finish();

            let vcode_offset = if let Some(&offset) = dedup.get(&hash) {
                self.duplicates += 1;
                offset
            } else {
                #[cfg(debug_assertions)]
                let before = operations
                    .iter()
                    .map(|operation| format!("{}", operation))
                    .collect::<Vec<String>>();

                let operations = permute::permute(operations);

                #[cfg(debug_assertions)]
                {
                    use logger::debug;

                    let mut log = false;

                    for instruction in &block.instructions {
                        if logged.insert(instruction.code()) {
                            log = true;
                        }
                    }

                    if log {
                        debug!(
                            "VIRTUALIZED @ 0x{:08X}:\n{}",
                            block.rva,
                            format_operations_with(&before, &operations)
                        );
                    }
                }

                let mut vblock = bytecode::assemble(&mut engine.rt.mapper, &operations);

                let key = u64::from_le_bytes(vcode[vcode.len() - 8..].try_into().unwrap());

                crypt::encrypt(
                    &mut vblock,
                    key,
                    self.keys.mul,
                    self.keys.add,
                    self.keys.att,
                );

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

        engine
            .rt
            .define_data_qword(DataDef::VmKeySeed, self.keys.seed);
        engine
            .rt
            .define_data_qword(DataDef::VmKeyMul, self.keys.mul);
        engine
            .rt
            .define_data_qword(DataDef::VmKeyAdd, self.keys.add);
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
