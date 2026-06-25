use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};

use std::{i32, slice};

use crate::engine::Engine;
use crate::protections::Protection;
use exe::{Buffer, SectionCharacteristics};
use exe::{PE, RVA};
use iced_x86::code_asm::CodeAssembler;
use iced_x86::Mnemonic;
use logger::info;
use rand::Rng;
use runtime::runtime::{DataDef, FnDef};
use runtime::vm::bytecode::{self};
use runtime::vm::encoders::Encode;
use runtime::{VM_DISPATCH_SIZE, VM_TRAMPOLINE_SIZE};

mod attestation;
pub mod crypt;
mod language;

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
    programs: Vec<Vec<Box<dyn Encode>>>,
    groups: Vec<Vec<u32>>,
    virtualized: HashMap<u32, usize>,
    trampolines: HashMap<u32, usize>,
    duplicates: usize,
    blocked: usize,
    missing: HashMap<Mnemonic, usize>,
}

impl Virtualization {
    fn attestation(&self, engine: &mut Engine) -> Vec<u8> {
        let mut vcode = Vec::new();

        #[cfg(debug_assertions)]
        let mut log = Vec::new();

        let blocks = attestation::generate(engine, self.keys.att);

        for (_index, operations) in blocks.into_iter().enumerate() {
            let mut rng = rand::thread_rng();

            #[cfg(debug_assertions)]
            let (transformed, snapshots) =
                bytecode::transform_with_snapshots(&mut engine.rt.mapper, operations, |ready| {
                    rng.gen_range(0..ready.len())
                });

            #[cfg(not(debug_assertions))]
            let transformed = bytecode::transform(&mut engine.rt.mapper, operations, |ready| {
                rng.gen_range(0..ready.len())
            });

            #[cfg(debug_assertions)]
            {
                let index = _index;
                log.push(format!("  BLOCK {}:\n{}", index, snapshots));
            }

            let mut bytes = bytecode::assemble(&mut engine.rt.mapper, &transformed);

            let key = if vcode.is_empty() {
                self.keys.seed
            } else {
                crypt::derive_key(&vcode)
            };

            crypt::encrypt_block(&mut bytes, key, self.keys.mul, self.keys.add, 0);
            crypt::decrypt_payload(&mut bytes, key, self.keys.mul, self.keys.add, 0);

            vcode.extend_from_slice(&bytes);
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
        #[cfg(debug_assertions)]
        const MAX_LOGGING: usize = 16;

        let mut vtable = Vec::new();

        #[cfg(debug_assertions)]
        let mut logs = Vec::new();

        let mut lookup = HashMap::new();

        'outer: for block in &mut engine.blocks {
            if block.size < VM_TRAMPOLINE_SIZE {
                continue;
            }

            let lifted = match bytecode::lift(&mut engine.rt.mapper, &block.instructions) {
                Some(ops) if !ops.is_empty() => ops,
                _ => {
                    self.blocked += 1;

                    let mut seen = HashSet::new();

                    for instruction in &block.instructions {
                        let mnemonic = instruction.mnemonic();

                        if !seen.insert(mnemonic) {
                            continue;
                        }

                        if bytecode::lift(&mut engine.rt.mapper, slice::from_ref(instruction))
                            .is_none()
                        {
                            *self.missing.entry(mnemonic).or_default() += 1;
                        }
                    }
                    continue 'outer;
                }
            };

            let mut hasher = DefaultHasher::new();
            bytecode::assemble(&mut engine.rt.mapper, &lifted).hash(&mut hasher);
            let hash = hasher.finish();

            if lookup.get(&hash).is_none() {
                let mut rng = rand::thread_rng();

                #[cfg(debug_assertions)]
                let transformed = if logs.len() < MAX_LOGGING {
                    let (transformed, snapshots) = bytecode::transform_with_snapshots(
                        &mut engine.rt.mapper,
                        lifted,
                        |ready| rng.gen_range(0..ready.len()),
                    );
                    logs.push((block.rva, format!("{}", snapshots)));
                    transformed
                } else {
                    bytecode::transform(&mut engine.rt.mapper, lifted, |ready| {
                        rng.gen_range(0..ready.len())
                    })
                };

                #[cfg(not(debug_assertions))]
                let transformed = bytecode::transform(&mut engine.rt.mapper, lifted, |ready| {
                    rng.gen_range(0..ready.len())
                });

                let index = self.programs.len();
                self.programs.push(transformed);

                self.groups.push(vec![block.rva]);

                lookup.insert(hash, index);
            } else {
                self.duplicates += 1;
                let index = lookup[&hash];
                self.groups[index].push(block.rva);
            }
        }

        for (_, group) in self.programs.iter().zip(&self.groups) {
            for &rva in group {
                // Store the index of this VM-block's VM-table entry
                let index = vtable.len() / 8;
                self.virtualized.insert(rva, index);

                // Store placeholders for stub displacement and bytecode offset
                vtable.extend_from_slice(&0u32.to_le_bytes());
                vtable.extend_from_slice(&0u32.to_le_bytes());
            }
        }

        // Reserve a trampoline slot for each block too small for an inline stub
        for block in &engine.blocks {
            if self.virtualized.contains_key(&block.rva) && block.size < VM_DISPATCH_SIZE {
                self.trampolines.insert(block.rva, self.trampolines.len());
            }
        }

        engine.rt.define_data_bytes(
            DataDef::VmTrampolines,
            &vec![0u8; self.trampolines.len() * VM_DISPATCH_SIZE],
        );

        #[cfg(debug_assertions)]
        {
            use logger::debug;

            for (rva, log) in logs {
                debug!("VIRTUALIZED @ 0x{:08X}:\n{}", rva, log);
            }
        }

        engine.rt.define_data_bytes(DataDef::VmTable, &vtable);

        engine.rt.define_data_dword(DataDef::VmCode, 0);

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
        let attestation = self.attestation(engine);

        let mut vcode = attestation;

        let vtable_rva = engine.rt.lookup(engine.rt.data_labels[&DataDef::VmTable]) as u32;
        let vtable_offset = engine.pe.translate(RVA(vtable_rva).into()).unwrap();
        let vtable = unsafe { engine.pe.as_ptr().add(vtable_offset) as *mut u8 };

        for (program, group) in self.programs.iter().zip(&self.groups) {
            let mut bytes = bytecode::assemble(&mut engine.rt.mapper, program);

            let key = crypt::derive_key(&vcode);

            crypt::encrypt_block(&mut bytes, key, self.keys.mul, self.keys.add, self.keys.att);

            let offset = TryInto::<u32>::try_into(vcode.len()).unwrap();
            vcode.extend_from_slice(&bytes);

            for &rva in group {
                let index = self.virtualized[&rva];
                unsafe {
                    vtable
                        .add(index * 8 + size_of::<u32>())
                        .copy_from(offset.to_le_bytes().as_ptr(), size_of::<u32>());
                }
            }
        }

        let section = engine.create_section(
            None,
            &vcode,
            SectionCharacteristics::CNT_INITIALIZED_DATA
                | SectionCharacteristics::MEM_READ
                | SectionCharacteristics::MEM_WRITE,
        );

        let vtable_rva = engine.rt.lookup(engine.rt.data_labels[&DataDef::VmTable]) as u32;
        let vtable_offset = engine.pe.translate(RVA(vtable_rva).into()).unwrap();
        let vtable = unsafe { engine.pe.as_ptr().add(vtable_offset) as *mut u8 };

        let vcode_rva = engine.rt.lookup(engine.rt.data_labels[&DataDef::VmCode]) as u32;
        let vcode_offset = engine.pe.translate(RVA(vcode_rva).into()).unwrap();
        let displacement = section.virtual_address.0 as i64 - vcode_rva as i64;
        engine
            .pe
            .write(vcode_offset, &(displacement as i32).to_le_bytes())
            .unwrap();

        let ventry_rva = engine.rt.lookup(engine.rt.function_labels[&FnDef::VmEntry]);

        let trampolines_rva = engine
            .rt
            .lookup(engine.rt.data_labels[&DataDef::VmTrampolines])
            as u32;
        let trampolines_offset = engine.pe.translate(RVA(trampolines_rva).into()).unwrap();
        let trampolines = unsafe { engine.pe.as_ptr().add(trampolines_offset) as *mut u8 };

        for i in 0..engine.blocks.len() {
            let rva = engine.blocks[i].rva;
            let size = engine.blocks[i].size;

            if !self.virtualized.contains_key(&rva) {
                continue;
            }

            let vtable_index = self.virtualized[&rva];

            if size >= VM_DISPATCH_SIZE {
                let mut asm = CodeAssembler::new(engine.bitness).unwrap();

                asm.push(vtable_index as i32 | 0x10000000).unwrap();
                asm.call(ventry_rva).unwrap();
                let dispatch1 = asm.assemble(rva as u64).unwrap();

                assert!(dispatch1.len() <= VM_DISPATCH_SIZE);

                asm.reset();

                // Stub has to be assembled twice so that the runtime return address can be calculated
                let return_address = rva as i32 + dispatch1.len() as i32;

                asm.push((vtable_index as i32 | 0x10000000) ^ return_address)
                    .unwrap();
                asm.call(ventry_rva).unwrap();
                let dispatch2 = asm.assemble(rva as u64).unwrap();

                assert_eq!(dispatch1.len(), dispatch2.len());

                // Patch the stub displacement placeholder in the VM-table
                unsafe {
                    let displacement = (size - dispatch2.len()) as u32;
                    vtable
                        .add(vtable_index * 8)
                        .copy_from(displacement.to_le_bytes().as_ptr(), size_of::<u32>());
                }

                engine.replace(i, &dispatch2);
            } else {
                let trampoline = self.trampolines[&rva];
                let trampoline_rva = trampolines_rva + (trampoline * VM_DISPATCH_SIZE) as u32;

                let mut asm = CodeAssembler::new(engine.bitness).unwrap();

                let return_address = trampoline_rva + VM_DISPATCH_SIZE as u32;

                asm.push((vtable_index as i32 | 0x10000000) ^ return_address as i32)
                    .unwrap();
                asm.call(ventry_rva).unwrap();
                let dispatch = asm.assemble(trampoline_rva as u64).unwrap();

                assert_eq!(dispatch.len(), VM_DISPATCH_SIZE);

                unsafe {
                    trampolines
                        .add(trampoline * VM_DISPATCH_SIZE)
                        .copy_from(dispatch.as_ptr(), VM_DISPATCH_SIZE);
                }

                // Patch the stub displacement placeholder in the VM-table to redirect to original block
                unsafe {
                    let displacement = (rva as i64 + size as i64 - return_address as i64) as i32;
                    vtable.add(vtable_index * 8).copy_from(
                        (displacement as u32).to_le_bytes().as_ptr(),
                        size_of::<u32>(),
                    );
                }

                asm.reset();

                asm.jmp(trampoline_rva as u64).unwrap();

                let branch = asm.assemble(rva as u64).unwrap();

                assert!(branch.len() <= size);

                engine.replace(i, &branch);
            }
        }

        info!(
            "VIRTUALIZED: {}/{} blocks ({:.2}%) [duplicates: {}]",
            self.virtualized.len(),
            engine.blocks.len(),
            (self.virtualized.len() as f64 / engine.blocks.len().max(1) as f64) * 100.0,
            self.duplicates
        );

        if self.blocked > 0 {
            info!(
                "MISSING: {}/{} blocks ({:.2}%)",
                self.blocked,
                engine.blocks.len(),
                (self.blocked as f64 / engine.blocks.len().max(1) as f64) * 100.0
            );

            let mut causes = self.missing.iter().collect::<Vec<(&Mnemonic, &usize)>>();
            causes.sort_by(|a, b| b.1.cmp(a.1));

            for (mnemonic, count) in causes {
                info!("    {} x {:?}", count, mnemonic);
            }
        }
    }
}
