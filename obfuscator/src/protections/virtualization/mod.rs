use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};

use std::{i32, slice};

use crate::engine::Engine;
use crate::protections::virtualization::crypt::Cipher;
use crate::protections::Protection;
use exe::{Buffer, SectionCharacteristics};
use exe::{PE, RVA};
use iced_x86::code_asm::{dword_ptr, rsp, CodeAssembler};
use iced_x86::Mnemonic;
use logger::{debug, info};
use rand::Rng;
use runtime::runtime::{DataDef, FnDef};
use runtime::vm::bytecode::{self};
use runtime::vm::encoders::Encode;
use runtime::{VM_DISPATCH_SIZE, VM_REDIRECT_SIZE, VM_TRAMPOLINE_SIZE};

mod attestation;
pub mod crypt;
mod language;

#[derive(Clone, Copy, Default)]
struct TableEntry {
    exit: u32,
    entry: u32,
    offset: u32,
}

impl TableEntry {
    fn new(rva: u32, size: usize, return_address: i32, offset: u32) -> Self {
        Self {
            exit: (rva as i64 + size as i64 - return_address as i64) as u32,
            entry: (rva as i64 - return_address as i64) as u32,
            offset,
        }
    }
}

impl From<TableEntry> for [u8; size_of::<TableEntry>()] {
    fn from(entry: TableEntry) -> Self {
        let mut bytes = [0u8; size_of::<TableEntry>()];
        bytes[0..4].copy_from_slice(&entry.exit.to_le_bytes());
        bytes[4..8].copy_from_slice(&entry.entry.to_le_bytes());
        bytes[8..12].copy_from_slice(&entry.offset.to_le_bytes());
        bytes
    }
}

fn resolve(engine: &Engine, label: DataDef) -> (u32, usize) {
    let rva = engine.rt.lookup(engine.rt.data_labels[&label]) as u32;
    let offset = engine.pe.translate(RVA(rva).into()).unwrap();
    (rva, offset)
}

fn write_displacement(engine: &mut Engine, label: DataDef, value: u32) {
    let (rva, offset) = resolve(engine, label);
    let displacement = (value as i64 - rva as i64) as i32;
    engine
        .pe
        .write(offset, &displacement.to_le_bytes())
        .unwrap();
}

fn write_entry(engine: &mut Engine, index: usize, entry: TableEntry) {
    let (_, offset) = resolve(engine, DataDef::VmTable);
    let bytes = <[u8; size_of::<TableEntry>()]>::from(entry);
    engine
        .pe
        .write(offset + index * size_of::<TableEntry>(), &bytes)
        .unwrap();
}

fn write_trampoline(engine: &mut Engine, redirect: usize, bytes: &[u8]) {
    let (_, offset) = resolve(engine, DataDef::VmTrampolines);
    engine
        .pe
        .write(offset + redirect * VM_REDIRECT_SIZE, bytes)
        .unwrap();
}

#[derive(Default)]
pub struct Virtualization {
    programs: Vec<Vec<u8>>,
    groups: Vec<Vec<u32>>,
    virtualized: HashMap<u32, usize>,
    redirects: HashMap<u32, usize>,
    duplicates: usize,
    blocked: usize,
    missing: HashMap<Mnemonic, usize>,
}

impl Virtualization {
    fn assemble(
        &self,
        engine: &mut Engine,
        operations: Vec<Box<dyn Encode>>,
        offset: u64,
        register: bool,
    ) -> Vec<u8> {
        let mut rng = rand::thread_rng();

        let mut operations = operations;
        bytecode::fuse(&mut engine.rt, &mut operations, register);

        let mut transformed = if engine.args.verbose {
            let (transformed, snapshots) = bytecode::transform_with_snapshots(
                &mut engine.rt.mapper,
                operations,
                offset,
                |ready| rng.gen_range(0..ready.len()),
            );

            if !register {
                debug!("ATTESTATION @ 0x{:08X}:\n{}", offset, snapshots);
            }

            transformed
        } else {
            bytecode::transform(&mut engine.rt.mapper, operations, offset, |ready| {
                rng.gen_range(0..ready.len())
            })
        };

        bytecode::fuse(&mut engine.rt, &mut transformed, register);

        let mut bytes = bytecode::assemble(&mut engine.rt.mapper, &transformed);

        let cipher = Cipher::new(engine.rt.keys.multiplier, engine.rt.keys.addend);
        cipher.encrypt_block(&mut bytes, 0, 0);
        cipher.decrypt_payload(&mut bytes, 0, 0);

        bytes
    }

    fn attestation(&self, engine: &mut Engine, base: u64, register: bool) -> (Vec<u8>, Vec<u8>) {
        let mut expected = 0;

        let service = attestation::service(engine, &mut expected);
        let program = attestation::program(engine, engine.rt.keys.secret, expected);

        let program = self.assemble(engine, program, base, register);
        let service = self.assemble(engine, service, base + program.len() as u64, register);

        (program, service)
    }
}

impl Protection for Virtualization {
    fn initialize(&mut self, engine: &mut Engine) {
        let mut log = Vec::new();

        let mut table = Vec::new();

        let mut lookup = HashMap::new();

        let mut code = Vec::new();

        let cipher = Cipher::new(engine.rt.keys.multiplier, engine.rt.keys.addend);

        let mut operations = Vec::new();

        'outer: for block in &mut engine.blocks {
            if block.size < VM_TRAMPOLINE_SIZE {
                continue;
            }

            let lifted = match bytecode::lift(&block.instructions) {
                Some(ops) if !ops.is_empty() => ops,
                _ => {
                    self.blocked += 1;

                    let mut seen = HashSet::new();

                    for instruction in &block.instructions {
                        let mnemonic = instruction.mnemonic();

                        if !seen.insert(mnemonic) {
                            continue;
                        }

                        if bytecode::lift(slice::from_ref(instruction)).is_none() {
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
                let index = operations.len();
                operations.push(lifted);
                self.groups.push(vec![block.rva]);
                lookup.insert(hash, index);
            } else {
                self.duplicates += 1;
                let index = lookup[&hash];
                self.groups[index].push(block.rva);
            }
        }

        let mut rng = rand::thread_rng();

        for (index, operations) in operations.into_iter().enumerate() {
            let offset = code.len() as u64;

            let mut operations = operations;
            bytecode::fuse(&mut engine.rt, &mut operations, true);

            let mut transformed = if engine.args.verbose {
                let (transformed, snapshots) = bytecode::transform_with_snapshots(
                    &mut engine.rt.mapper,
                    operations,
                    offset,
                    |ready| rng.gen_range(0..ready.len()),
                );

                log.push((self.groups[index][0], format!("{}", snapshots)));

                transformed
            } else {
                bytecode::transform(&mut engine.rt.mapper, operations, offset, |ready| {
                    rng.gen_range(0..ready.len())
                })
            };

            bytecode::fuse(&mut engine.rt, &mut transformed, true);

            let mut bytes = bytecode::assemble(&mut engine.rt.mapper, &transformed);

            cipher.encrypt_block(&mut bytes, 0, 0);
            cipher.decrypt_payload(&mut bytes, 0, 0);

            code.extend_from_slice(&bytes);

            self.programs.push(bytes);
        }

        for (_, group) in self.programs.iter().zip(&self.groups) {
            for &rva in group {
                let index = table.len() / size_of::<TableEntry>();
                self.virtualized.insert(rva, index);

                table.extend_from_slice(&<[u8; size_of::<TableEntry>()]>::from(
                    TableEntry::default(),
                ));
            }
        }

        // Reserve a trampoline slot for each block too small for an inline stub:
        for block in &engine.blocks {
            if self.virtualized.contains_key(&block.rva) && block.size < VM_DISPATCH_SIZE {
                self.redirects.insert(block.rva, self.redirects.len());
            }
        }

        engine.rt.define_data_bytes(
            DataDef::VmTrampolines,
            &vec![0u8; self.redirects.len() * VM_REDIRECT_SIZE],
        );

        if engine.args.verbose {
            for (rva, log) in log {
                debug!("VIRTUALIZED @ 0x{:08X}:\n{}", rva, log);
            }
        }

        engine.rt.define_data_bytes(DataDef::VmTable, &table);

        engine.rt.define_data_dword(DataDef::VmCodeStart, 0);
        engine.rt.define_data_dword(DataDef::VmCodeEnd, 0);
        engine
            .rt
            .define_data_dword(DataDef::VmAttestationProgram, 0);
        engine
            .rt
            .define_data_dword(DataDef::VmAttestationService, 0);

        engine
            .rt
            .define_data_qword(DataDef::VmKeyInitializer, engine.rt.keys.initializer);
        engine
            .rt
            .define_data_qword(DataDef::VmKeyMultiplier, engine.rt.keys.multiplier);
        engine
            .rt
            .define_data_qword(DataDef::VmKeyAddend, engine.rt.keys.addend);

        self.attestation(engine, 0, true);
    }

    fn apply(&self, engine: &mut Engine) {
        let mut code = Vec::new();
        let mut offsets = vec![0u32; self.virtualized.len()];

        for (bytes, group) in self.programs.iter().zip(&self.groups) {
            let offset = TryInto::<u32>::try_into(code.len()).unwrap();
            code.extend_from_slice(bytes);

            for &rva in group {
                offsets[self.virtualized[&rva]] = offset;
            }
        }

        let attestation = code.len();

        let (program, service) = self.attestation(engine, attestation as u64, false);

        let cipher = Cipher::new(engine.rt.keys.multiplier, engine.rt.keys.addend);

        let region = [program.as_slice(), service.as_slice()].concat();
        let hash = crypt::derive_hash(&region, engine.rt.keys.multiplier, engine.rt.keys.addend);

        let secret = engine.rt.keys.secret ^ hash;
        let mut key = engine.rt.keys.initializer;

        let mut position = 0;

        for bytes in &self.programs {
            let block = &mut code[position..position + bytes.len()];

            cipher.encrypt_payload(block, key, secret);

            key = crypt::derive_key(block);

            position += bytes.len();
        }

        code.extend_from_slice(&program);
        code.extend_from_slice(&service);

        let section = engine.create_section(
            Some("☠️"),
            &code,
            SectionCharacteristics::CNT_INITIALIZED_DATA
                | SectionCharacteristics::MEM_READ
                | SectionCharacteristics::MEM_WRITE,
        );
        let base = section.virtual_address.0;

        write_displacement(engine, DataDef::VmCodeStart, base);
        write_displacement(engine, DataDef::VmCodeEnd, base + code.len() as u32);
        write_displacement(
            engine,
            DataDef::VmAttestationProgram,
            base + attestation as u32,
        );
        write_displacement(
            engine,
            DataDef::VmAttestationService,
            base + (attestation + program.len()) as u32,
        );

        let entry_rva = engine.rt.lookup(engine.rt.function_labels[&FnDef::VmEntry]);

        let redirects_rva = engine
            .rt
            .lookup(engine.rt.data_labels[&DataDef::VmTrampolines])
            as u32;

        let multiplier = engine.rt.keys.multiplier;
        let addend = engine.rt.keys.addend;

        for i in 0..engine.blocks.len() {
            let rva = engine.blocks[i].rva;
            let size = engine.blocks[i].size;

            if !self.virtualized.contains_key(&rva) {
                continue;
            }

            let index = self.virtualized[&rva];

            let token = ((index as u64).wrapping_mul(multiplier).wrapping_add(addend) & 0x0FFFFFFF)
                as i32
                | 0x10000000;

            let mut asm = CodeAssembler::new(engine.bitness).unwrap();

            if size >= VM_DISPATCH_SIZE {
                asm.push(token).unwrap();
                asm.call(entry_rva).unwrap();
                let first = asm.assemble(rva as u64).unwrap();

                assert!(first.len() <= VM_DISPATCH_SIZE);

                asm.reset();

                // Stub has to be assembled twice so that the runtime return address can be calculated:
                let return_address = rva as i32 + first.len() as i32;

                asm.push(token ^ return_address).unwrap();
                asm.call(entry_rva).unwrap();
                let second = asm.assemble(rva as u64).unwrap();

                assert_eq!(first.len(), second.len());

                write_entry(
                    engine,
                    index,
                    TableEntry::new(rva, size, return_address, offsets[index]),
                );

                engine.replace(i, &second);
            } else {
                let redirect = self.redirects[&rva];
                let redirect_rva = redirects_rva + (redirect * VM_REDIRECT_SIZE) as u32;

                let return_address = (redirect_rva + VM_REDIRECT_SIZE as u32) as i32;

                asm.mov(dword_ptr(rsp), token ^ return_address).unwrap();
                asm.call(entry_rva).unwrap();
                let dispatch = asm.assemble(redirect_rva as u64).unwrap();

                assert_eq!(dispatch.len(), VM_REDIRECT_SIZE);

                write_trampoline(engine, redirect, &dispatch);
                write_entry(
                    engine,
                    index,
                    TableEntry::new(rva, size, return_address, offsets[index]),
                );

                asm.reset();

                asm.call(redirect_rva as u64).unwrap();
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
                info!("{}{} x {:?}", " ".repeat(4), count, mnemonic);
            }
        }
    }
}
