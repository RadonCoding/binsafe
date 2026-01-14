
// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\obfuscator\Cargo.toml =====

[package]
name = "obfuscator"
version = "0.1.0"
edition = "2021"

[dependencies]
exe = "0.5.6"
iced-x86 = { version = "1.21.0", features = ["code_asm"] }
rand = "0.8.5"
clap = { version = "4.5.53", features = ["derive"] }
logger = { path = "../logger" }
runtime = { path = "../runtime" }

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\obfuscator\src\engine.rs =====

use exe::{
    Arch, Buffer, ImageSectionHeader, Offset, PETranslation, RelocationDirectory, RelocationValue,
    SectionCharacteristics, VecPE, PE, RVA,
};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter};
use logger::info;
use rand::Rng;
use runtime::runtime::Runtime;
use std::{collections::HashSet, fmt, mem, path::Path};

use crate::{exceptions, protections::Protection};

pub struct Block {
    pub rva: u32,
    pub offset: usize,
    pub size: usize,
    pub instructions: Vec<Instruction>,
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "Block [offset: 0x{:X}, size: {} bytes]",
            self.offset, self.size
        )?;

        let mut formatter = IntelFormatter::new();
        let mut output = String::new();

        for instruction in &self.instructions {
            output.clear();
            formatter.format(instruction, &mut output);

            let rva = instruction.ip() as u32;
            writeln!(f, "{:08X}  {}", rva, output)?;
        }

        Ok(())
    }
}

pub struct Engine {
    pub pe: VecPE,
    pub bitness: u32,
    pub blocks: Vec<Block>,
    pub rt: Runtime,
    protections: Vec<Box<dyn Protection>>,
}

impl Engine {
    pub fn new(filename: &Path) -> Self {
        let pe = VecPE::from_disk_file(&filename).unwrap();

        let bitness = match pe.get_arch().unwrap() {
            Arch::X64 => 64,
            _ => panic!("only 64-bit binaries are supported"),
        };

        info!(
            "Loaded {}-bit binary ({:.2} MB)",
            bitness,
            pe.len() as f64 / 1_000_000.0,
        );

        Self {
            pe,
            bitness,
            blocks: Vec::new(),
            rt: Runtime::new(bitness),
            protections: Vec::new(),
        }
    }

    pub fn apply<T: Protection + Default + 'static>(&mut self) {
        self.protections.push(Box::<T>::default());
    }

    pub fn replace(&mut self, index: usize, data: &[u8]) {
        let block = &mut self.blocks[index];

        assert!(data.len() <= block.size);

        let mut padded = data.to_vec();

        let remaining = block.size - padded.len();

        if remaining > 0 {
            let mut junk = vec![0u8; remaining];
            rand::thread_rng().fill(&mut junk[..]);

            padded.extend(junk);
        }

        self.pe.write(block.offset, padded).unwrap();

        let bytes = self
            .pe
            .get_slice_ref::<u8>(block.offset, block.size)
            .unwrap();

        let mut decoder =
            Decoder::with_ip(self.bitness, bytes, block.rva as u64, DecoderOptions::NONE);

        block.instructions.clear();

        while decoder.can_decode() {
            let mut instruction = Instruction::default();
            decoder.decode_out(&mut instruction);

            if instruction.is_invalid() {
                break;
            }
            block.instructions.push(instruction);
        }
    }

    pub fn scan(&mut self) {
        let image_base = self.pe.get_image_base().unwrap();

        let entry_point = self.pe.get_entrypoint().unwrap();

        let code_section = self.pe.get_section_by_rva(entry_point).unwrap();

        info!(
            "Protecting section '{}' at 0x{:08X}",
            Self::get_section_name(code_section),
            code_section.virtual_address.0
        );

        let ip = code_section.virtual_address.0 as u64;
        let code = code_section.read(&self.pe).unwrap();

        let mut jumps = HashSet::new();
        jumps.insert(entry_point.0);

        let handlers = exceptions::get_exception_handlers(&self.pe);

        for handler in handlers {
            if code_section.has_rva(RVA(handler)) {
                jumps.insert(handler);
            }
        }

        if let Ok(relocs) = RelocationDirectory::parse(&self.pe) {
            if let Ok(entries) = relocs.relocations(&self.pe, image_base) {
                for (_, value) in entries {
                    let target_va = match value {
                        RelocationValue::Relocation32(v) => v as u64,
                        RelocationValue::Relocation64(v) => v,
                        _ => continue,
                    };

                    let target_rva = (target_va - image_base) as u32;

                    if code_section.has_rva(RVA(target_rva)) {
                        jumps.insert(target_rva);
                    }
                }
            }
        }

        let mut decoder = Decoder::with_ip(self.bitness, &code, ip, DecoderOptions::NONE);

        let mut instruction = Instruction::default();

        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);

            if instruction.is_invalid() {
                continue;
            }

            match instruction.flow_control() {
                FlowControl::ConditionalBranch
                | FlowControl::UnconditionalBranch
                | FlowControl::Call => {
                    let target = instruction.near_branch_target() as u32;

                    if code_section.has_rva(RVA(target)) {
                        jumps.insert(target);
                    }
                }
                _ => {}
            }
        }

        let mut sorted = jumps.into_iter().collect::<Vec<u32>>();
        sorted.sort();

        let mut capture = |block: &mut Vec<Instruction>, end: u32| {
            if block.is_empty() {
                return;
            }
            let start = block[0].ip() as u32;
            let offset = self
                .pe
                .translate(PETranslation::Memory(RVA(start as u32)))
                .unwrap();
            let size = (end - start) as usize;
            self.blocks.push(Block {
                rva: start,
                offset,
                size,
                instructions: mem::take(block),
            });
        };

        let mut decoder = Decoder::with_ip(self.bitness, &code, ip, DecoderOptions::NONE);
        let mut block = Vec::<Instruction>::new();
        let mut inblock = false;

        while decoder.can_decode() {
            let current = decoder.ip() as u32;

            if sorted.binary_search(&current).is_ok() {
                if inblock {
                    capture(&mut block, current);
                }
                inblock = true;
            }

            if !inblock {
                decoder.decode_out(&mut instruction);
                continue;
            }

            decoder.decode_out(&mut instruction);

            if instruction.is_invalid() {
                inblock = false;
                continue;
            }

            let start = instruction.ip() as u32;
            let end = instruction.next_ip() as u32;

            let pos = sorted.binary_search(&end).unwrap_or_else(|e| e);

            let overlaps = if pos > 0 && sorted[pos - 1] > start && sorted[pos - 1] < end {
                true
            } else {
                false
            };

            if overlaps {
                capture(&mut block, start);
                inblock = false;
                continue;
            }

            block.push(instruction);

            if instruction.flow_control() != FlowControl::Next {
                let next = instruction.next_ip() as u32;
                capture(&mut block, next);
                inblock = false;
            }
        }

        info!("Found {} blocks", self.blocks.len());
    }

    pub fn get_start_of_next_section(&self) -> u32 {
        let sections = self.pe.get_section_table().unwrap();
        let last_section = sections[sections.len() - 1];
        self.pe
            .align_to_section(RVA(
                last_section.virtual_address.0 + last_section.virtual_size
            ))
            .unwrap()
            .0
    }

    pub fn get_section_name(section: &ImageSectionHeader) -> String {
        let bytes = section.name.iter().map(|c| c.0).collect::<Vec<u8>>();
        String::from_utf8_lossy(&bytes)
            .trim_end_matches('\0')
            .to_string()
    }

    pub fn create_section(
        &mut self,
        name: Option<&str>,
        content: &[u8],
        characteristics: SectionCharacteristics,
    ) -> ImageSectionHeader {
        let size = content.len() as u32;

        let virtual_size = self.pe.align_to_section(RVA(size)).unwrap().0;
        let raw_size = self.pe.align_to_file(Offset(size)).unwrap().0;

        let section = self
            .pe
            .append_section(&ImageSectionHeader::default())
            .unwrap();
        section.set_name(name);
        section.virtual_size = virtual_size;
        section.size_of_raw_data = raw_size;
        section.characteristics = characteristics;

        let section = *section;

        self.pe.append(content);
        self.pe.pad_to_alignment().unwrap();

        self.pe.fix_image_size().unwrap();

        section
    }

    pub fn execute(&mut self) -> Vec<u8> {
        let mut protections = mem::take(&mut self.protections);

        for protection in &mut protections {
            protection.initialize(self);
        }

        let ip = self.get_start_of_next_section();

        let code = self.rt.assemble(ip as u64);
        self.create_section(
            Some("💀"),
            &code,
            SectionCharacteristics::CNT_CODE
                | SectionCharacteristics::MEM_EXECUTE
                | SectionCharacteristics::MEM_READ
                | SectionCharacteristics::MEM_WRITE,
        );

        for protection in &protections {
            protection.apply(self);
        }

        let output = self.pe.to_vec();

        info!(
            "Rebuilt {}-bit binary ({:.2} MB)",
            self.bitness,
            self.pe.len() as f64 / 1_000_000.0,
        );

        output
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\obfuscator\src\exceptions.rs =====

use exe::{Buffer, Castable, ImageDirectoryEntry, PETranslation, VecPE, PE};
use std::{collections::HashSet, mem};

#[repr(C, packed)]
struct RuntimeFunction {
    begin_address: u32,
    end_address: u32,
    unwind_info_address: u32,
}
unsafe impl Castable for RuntimeFunction {}

pub fn get_exception_handlers(pe: &VecPE) -> HashSet<u32> {
    let mut results = HashSet::new();

    let exceptions = pe
        .get_data_directory(ImageDirectoryEntry::Exception)
        .unwrap();

    if exceptions.virtual_address.0 == 0 || exceptions.size == 0 {
        return results;
    }

    let offset = pe
        .translate(PETranslation::Memory(exceptions.virtual_address))
        .unwrap();
    let size = exceptions.size as usize / mem::size_of::<RuntimeFunction>();
    let functions = pe.get_slice_ref::<RuntimeFunction>(offset, size).unwrap();

    for rf in functions {
        results.insert(rf.begin_address);
        results.insert(rf.end_address);
    }

    results
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\obfuscator\src\main.rs =====

mod engine;
mod exceptions;
mod protections;

use clap::Parser;
use logger::info;
use std::{fs, path::PathBuf};

use crate::{
    engine::Engine,
    protections::{mutation::Mutation, virtualization::Virtualization},
};

#[derive(Parser)]
#[command(author, version)]
struct Args {
    input: PathBuf,

    #[arg(short = 'v', long = "virtualize")]
    virtualize: bool,

    #[arg(short = 'm', long = "mutate")]
    mutate: bool,
}

fn main() {
    let args = Args::parse();

    let input = &args.input;

    let mut engine = Engine::new(input);

    engine.scan();

    if args.virtualize {
        engine.apply::<Virtualization>();
    }

    if args.mutate {
        engine.apply::<Mutation>();
    }

    let protected = engine.execute();

    let output = if let Some(extension) = input.extension() {
        input.with_extension("").with_file_name(format!(
            "{}.protected.{}",
            input.file_stem().unwrap().to_str().unwrap(),
            extension.to_str().unwrap()
        ))
    } else {
        let mut output = input.to_path_buf();
        output.set_file_name(format!(
            "{}.protected",
            input.file_name().unwrap().to_str().unwrap()
        ));
        output
    };

    fs::write(&output, protected).unwrap();

    info!("Wrote output to '{}'", output.display());
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\obfuscator\src\protections\mod.rs =====

use crate::engine::Engine;

pub mod mutation;
pub mod virtualization;

pub trait Protection {
    fn initialize(&mut self, engine: &mut Engine);

    fn apply(&self, engine: &mut Engine);
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\obfuscator\src\protections\mutation.rs =====

use crate::engine::Engine;
use crate::protections::Protection;
use iced_x86::code_asm::*;
use iced_x86::{Instruction, Mnemonic, OpKind, Register};
use logger::info;
use rand::Rng;

#[derive(Default)]
pub struct Mutation;

impl Mutation {
    fn resolve_gpr32(&self, reg: Register) -> Option<AsmRegister32> {
        use iced_x86::code_asm::registers::gpr32::*;
        match reg {
            Register::EAX => Some(eax),
            Register::ECX => Some(ecx),
            Register::EDX => Some(edx),
            Register::EBX => Some(ebx),
            Register::ESP => Some(esp),
            Register::EBP => Some(ebp),
            Register::ESI => Some(esi),
            Register::EDI => Some(edi),
            Register::R8D => Some(r8d),
            Register::R9D => Some(r9d),
            Register::R10D => Some(r10d),
            Register::R11D => Some(r11d),
            Register::R12D => Some(r12d),
            Register::R13D => Some(r13d),
            Register::R14D => Some(r14d),
            Register::R15D => Some(r15d),
            _ => None,
        }
    }

    fn resolve_gpr64(&self, reg: Register) -> Option<AsmRegister64> {
        use iced_x86::code_asm::registers::gpr64::*;
        match reg {
            Register::RAX => Some(rax),
            Register::RCX => Some(rcx),
            Register::RDX => Some(rdx),
            Register::RBX => Some(rbx),
            Register::RSP => Some(rsp),
            Register::RBP => Some(rbp),
            Register::RSI => Some(rsi),
            Register::RDI => Some(rdi),
            Register::R8 => Some(r8),
            Register::R9 => Some(r9),
            Register::R10 => Some(r10),
            Register::R11 => Some(r11),
            Register::R12 => Some(r12),
            Register::R13 => Some(r13),
            Register::R14 => Some(r14),
            Register::R15 => Some(r15),
            _ => None,
        }
    }

    fn has_dead_flags(&self, instructions: &[Instruction]) -> bool {
        let written_flags = instructions[0].rflags_written();

        for i in 1..instructions.len() {
            let instruction = &instructions[i];

            if (instruction.rflags_read() & written_flags) != 0 {
                return false;
            }

            if (instruction.rflags_written() & written_flags) == written_flags {
                return true;
            }
        }

        true
    }
}

impl Protection for Mutation {
    fn initialize(&mut self, _engine: &mut Engine) {}

    fn apply(&self, engine: &mut Engine) {
        let mut rng = rand::thread_rng();

        for i in 0..engine.blocks.len() {
            let block = &engine.blocks[i];

            let mut asm = CodeAssembler::new(engine.bitness).unwrap();

            let mut mutated = false;

            for (index, instruction) in block.instructions.iter().enumerate() {
                let dead_flags = self.has_dead_flags(&block.instructions[index..]);
                let mnemonic = instruction.mnemonic();
                let raw = instruction.op0_register();

                // MOV reg, imm -> MOV reg, (imm^key); XOR reg, key
                if mnemonic == Mnemonic::Mov
                    && instruction.op1_kind() == OpKind::Immediate32
                    && dead_flags
                {
                    let imm = instruction.immediate(1);
                    let key = rng.gen::<u32>();

                    if let Some(reg) = self.resolve_gpr64(raw) {
                        asm.mov(reg, imm ^ (key as u64)).unwrap();
                        asm.xor(reg, key as i32).unwrap();
                        mutated = true;
                        continue;
                    } else if let Some(reg) = self.resolve_gpr32(raw) {
                        asm.mov(reg, (imm as u32) ^ key).unwrap();
                        asm.xor(reg, key as i32).unwrap();
                        mutated = true;
                        continue;
                    }
                }

                // ADD/SUB reg, imm -> SUB/ADD reg, -imm
                if (mnemonic == Mnemonic::Add || mnemonic == Mnemonic::Sub)
                    && instruction.op1_kind() == OpKind::Immediate32
                    && dead_flags
                {
                    let imm = instruction.immediate(1) as i32;
                    let addition = mnemonic == Mnemonic::Add;

                    if let Some(reg) = self.resolve_gpr64(raw) {
                        if addition {
                            asm.sub(reg, -imm).unwrap();
                        } else {
                            asm.add(reg, -imm).unwrap();
                        }
                        mutated = true;
                        continue;
                    } else if let Some(reg) = self.resolve_gpr32(raw) {
                        if addition {
                            asm.sub(reg, -imm).unwrap();
                        } else {
                            asm.add(reg, -imm).unwrap();
                        }
                        mutated = true;
                        continue;
                    }
                }

                // XOR reg, imm -> NOT reg; XOR reg, !imm
                if mnemonic == Mnemonic::Xor
                    && instruction.op1_kind() == OpKind::Immediate32
                    && dead_flags
                {
                    let imm = instruction.immediate(1) as i32;

                    if let Some(reg) = self.resolve_gpr64(raw) {
                        asm.not(reg).unwrap();
                        asm.xor(reg, !imm).unwrap();
                        mutated = true;
                        continue;
                    } else if let Some(reg) = self.resolve_gpr32(raw) {
                        asm.not(reg).unwrap();
                        asm.xor(reg, !imm).unwrap();
                        mutated = true;
                        continue;
                    }
                }

                // AND reg, imm -> NOT reg; OR reg, !imm; NOT reg
                if mnemonic == Mnemonic::And
                    && instruction.op1_kind() == OpKind::Immediate32
                    && dead_flags
                {
                    let imm = instruction.immediate(1) as i32;

                    if let Some(reg) = self.resolve_gpr64(raw) {
                        asm.not(reg).unwrap();
                        asm.or(reg, !imm).unwrap();
                        asm.not(reg).unwrap();
                        mutated = true;
                        continue;
                    } else if let Some(reg) = self.resolve_gpr32(raw) {
                        asm.not(reg).unwrap();
                        asm.or(reg, !imm).unwrap();
                        asm.not(reg).unwrap();
                        mutated = true;
                        continue;
                    }
                }

                // OR reg, imm -> NOT reg; AND reg, !imm; NOT reg
                if mnemonic == Mnemonic::Or
                    && instruction.op1_kind() == OpKind::Immediate32
                    && dead_flags
                {
                    let imm = instruction.immediate(1) as i32;

                    if let Some(reg) = self.resolve_gpr64(raw) {
                        asm.not(reg).unwrap();
                        asm.and(reg, !imm).unwrap();
                        asm.not(reg).unwrap();
                        mutated = true;
                        continue;
                    } else if let Some(reg) = self.resolve_gpr32(raw) {
                        asm.not(reg).unwrap();
                        asm.and(reg, !imm).unwrap();
                        asm.not(reg).unwrap();
                        mutated = true;
                        continue;
                    }
                }

                // NEG reg -> NOT reg; ADD reg, 1
                if mnemonic == Mnemonic::Neg && dead_flags {
                    if let Some(reg) = self.resolve_gpr64(raw) {
                        asm.not(reg).unwrap();
                        asm.add(reg, 1).unwrap();
                        mutated = true;
                        continue;
                    } else if let Some(reg) = self.resolve_gpr32(raw) {
                        asm.not(reg).unwrap();
                        asm.add(reg, 1).unwrap();
                        mutated = true;
                        continue;
                    }
                }

                // SUB reg, reg -> XOR reg, reg
                if mnemonic == Mnemonic::Sub
                    && instruction.op0_kind() == OpKind::Register
                    && instruction.op1_kind() == OpKind::Register
                {
                    if raw == instruction.op1_register() && dead_flags {
                        if let Some(reg) = self.resolve_gpr64(raw) {
                            asm.xor(reg, reg).unwrap();
                            mutated = true;
                            continue;
                        } else if let Some(reg) = self.resolve_gpr32(raw) {
                            asm.xor(reg, reg).unwrap();
                            mutated = true;
                            continue;
                        }
                    }
                }

                asm.add_instruction(*instruction).unwrap();
            }

            if mutated {
                let bytes = asm.assemble(block.rva as u64).unwrap();

                if bytes.len() <= block.size {
                    info!("PRE-MUTATION:\n{}", engine.blocks[i]);
                    engine.replace(i, &bytes);
                    info!("POST-MUTATION:\n{}", engine.blocks[i]);
                }
            }
        }
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\obfuscator\src\protections\virtualization\mod.rs =====

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

// First byte of NtQueryInformationProcess which is hooked by many anti-anti-debug implementations
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

        let anti_debug = AntiDebug::new(&engine.blocks);

        'outer: for block in &mut engine.blocks {
            if block.size < VDISPATCH_SIZE {
                continue;
            }

            let mut vblock = match bytecode::convert(&mut engine.rt.mapper, &block.instructions) {
                Some(virtualized) => virtualized,
                None => continue 'outer,
            };

            if let Some(bytecode) = anti_debug.transform(&mut engine.rt.mapper, block) {
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

            vtable.extend_from_slice(&0u32.to_le_bytes());
            vtable.extend_from_slice(&vcode_offset.to_le_bytes());
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

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\obfuscator\src\protections\virtualization\transforms\anti_debug.rs =====

use std::collections::HashMap;

use rand::{seq::SliceRandom, Rng};
use runtime::{
    mapper::Mapper,
    vm::{
        bytecode::{VMBits, VMCmd, VMMem, VMOp, VMReg, VMSeg},
        veh::TRAP_MAGIC,
    },
};

use crate::engine::Block;

pub struct AntiDebug {
    traps: HashMap<u32, TrapType>,
}

#[derive(Clone, Copy)]
enum TrapType {
    FakeException,
    PebCheck,
}

impl AntiDebug {
    pub fn new(blocks: &[Block]) -> Self {
        let mut traps = HashMap::new();

        let mut all = blocks.iter().map(|b| b.rva).collect::<Vec<u32>>();
        let mut relative = blocks
            .iter()
            .filter(|b| b.instructions.iter().any(|i| i.is_ip_rel_memory_operand()))
            .map(|b| b.rva)
            .collect::<Vec<u32>>();

        let exception_quota = (blocks.len() * 5 / 100).max(1);
        let peb_quota = (relative.len() * 25 / 100).max(1);

        let mut rng = rand::thread_rng();
        all.shuffle(&mut rng);
        relative.shuffle(&mut rng);

        for &idx in all.iter().take(exception_quota) {
            traps.insert(idx, TrapType::FakeException);
        }

        let mut peb_traps = 0;

        for &idx in &relative {
            if peb_traps >= peb_quota {
                break;
            }
            if !traps.contains_key(&idx) {
                traps.insert(idx, TrapType::PebCheck);
                peb_traps += 1;
            }
        }

        Self { traps }
    }

    pub fn transform(&self, mapper: &mut Mapper, block: &Block) -> Option<Vec<u8>> {
        match self.traps.get(&block.rva) {
            Some(TrapType::FakeException) => Some(Self::fake_exception(mapper)),
            Some(TrapType::PebCheck) => Some(Self::peb_check(mapper)),
            None => None,
        }
    }

    fn fake_exception(mapper: &mut Mapper) -> Vec<u8> {
        let mut rng = rand::thread_rng();

        let skip: u8 = rng.gen_range(4..=96);

        let mut junk = vec![0u8; skip as usize];
        rng.fill(&mut junk[..]);

        // Set the first type of the junk to a valid operation
        junk[0] = rng.gen_range(0..mapper.count::<VMOp>()) as u8;

        let entropy: u16 = rng.gen();

        let displacement: i32 =
            ((TRAP_MAGIC as i32) << 24) | ((skip as i32) << 16) | (entropy as i32);

        let trap = VMCmd::SetRegMem {
            vop: VMOp::SetRegMem,
            dbits: VMBits::Lower64,
            load: true,
            dst: VMReg::V0,
            src: VMMem {
                base: VMReg::None,
                index: VMReg::None,
                scale: 1,
                displacement,
                seg: VMSeg::None,
            },
        };

        let mut encoded = trap.encode(mapper);
        encoded.extend_from_slice(&junk);

        encoded
    }

    fn peb_check(mapper: &mut Mapper) -> Vec<u8> {
        let vinstructions: Vec<VMCmd<'static>> = vec![
            VMCmd::SetRegReg {
                vop: VMOp::SetRegReg,
                dbits: VMBits::Lower64,
                dst: VMReg::V1,
                sbits: VMBits::Lower64,
                src: VMReg::Flags,
            },
            // PEB *TEB->ProcessEnvironmentBlock
            VMCmd::SetRegMem {
                vop: VMOp::SetRegMem,
                dbits: VMBits::Lower64,
                load: true,
                dst: VMReg::V0,
                src: VMMem {
                    base: VMReg::None,
                    index: VMReg::None,
                    scale: 1,
                    displacement: 0x60,
                    seg: VMSeg::Gs,
                },
            },
            // BOOLEAN PEB->BeingDebugged
            VMCmd::AddSubRegMem {
                vop: VMOp::AddSubRegMem,
                sub: true,
                store: true,
                dbits: VMBits::Lower8,
                dst: VMReg::VB,
                src: VMMem {
                    base: VMReg::V0,
                    index: VMReg::None,
                    scale: 1,
                    displacement: 0x02,
                    seg: VMSeg::None,
                },
            },
            VMCmd::SetRegReg {
                vop: VMOp::SetRegReg,
                dbits: VMBits::Lower64,
                dst: VMReg::Flags,
                sbits: VMBits::Lower64,
                src: VMReg::V1,
            },
        ];

        vinstructions
            .into_iter()
            .flat_map(|cmd| cmd.encode(mapper))
            .collect()
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\obfuscator\src\protections\virtualization\transforms\mod.rs =====

pub mod anti_debug;

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\Cargo.toml =====

[package]
name = "runtime"
version = "0.1.0"
edition = "2021"

[dependencies]
iced-x86 = { version = "1.21.0", features = ["code_asm"] }
rand = "0.8.5"
strum = "0.27.2"
strum_macros = "0.27.2"

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\functions\compare_ansi.rs =====

use crate::runtime::Runtime;

use iced_x86::code_asm::{al, byte_ptr, r8b, rax, rcx, rdx, word_ptr};

// bool (const char*, const char*)
pub fn build(rt: &mut Runtime) {
    let mut compare_loop = rt.asm.create_label();
    let mut not_equal = rt.asm.create_label();
    let mut is_equal = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // mov al, byte ptr [rcx]
    rt.asm.mov(al, word_ptr(rcx)).unwrap();
    // mov r8b, byte ptr [rdx]
    rt.asm.mov(r8b, byte_ptr(rdx)).unwrap();

    rt.asm.set_label(&mut compare_loop).unwrap();
    {
        // cmp al, bl
        rt.asm.cmp(al, r8b).unwrap();
        // jne ...
        rt.asm.jne(not_equal).unwrap();

        // test al, al
        rt.asm.test(al, al).unwrap();
        // jz ...
        rt.asm.jz(is_equal).unwrap();

        // inc rcx
        rt.asm.inc(rcx).unwrap();
        // inc rdx
        rt.asm.inc(rdx).unwrap();

        // mov al, byte ptr [rcx]
        rt.asm.mov(al, word_ptr(rcx)).unwrap();
        // mov r8b, byte ptr [rdx]
        rt.asm.mov(r8b, byte_ptr(rdx)).unwrap();

        // jmp ...
        rt.asm.jmp(compare_loop).unwrap();
    }

    rt.asm.set_label(&mut not_equal).unwrap();
    {
        // mov rax, 0x0
        rt.asm.mov(rax, 0x0u64).unwrap();
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut is_equal).unwrap();
    {
        // mov rax, 0x1
        rt.asm.mov(rax, 0x1u64).unwrap();
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // ret
        rt.asm.ret().unwrap();
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\functions\compare_unicode_to_ansi.rs =====

use iced_x86::code_asm::{ax, byte_ptr, r8w, rax, rcx, rdx, word_ptr};

use crate::runtime::Runtime;

// bool (unsigned short*, char*)
pub fn build(rt: &mut Runtime) {
    let mut compare_loop = rt.asm.create_label();
    let mut not_equal = rt.asm.create_label();
    let mut is_equal = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // movzx ax, word ptr [rcx]
    rt.asm.movzx(ax, word_ptr(rcx)).unwrap();
    // movzx r8w, byte ptr [rdx]
    rt.asm.movzx(r8w, byte_ptr(rdx)).unwrap();

    rt.asm.set_label(&mut compare_loop).unwrap();
    {
        // cmp ax, r8w
        rt.asm.cmp(ax, r8w).unwrap();
        // jne ...
        rt.asm.jne(not_equal).unwrap();

        // test ax, ax
        rt.asm.test(ax, ax).unwrap();
        // jz ...
        rt.asm.jz(is_equal).unwrap();

        // add rcx, 0x2
        rt.asm.add(rcx, 0x2).unwrap();
        // add rdx, 0x1
        rt.asm.add(rdx, 0x1).unwrap();

        // movzx eax, word ptr [rcx]
        rt.asm.movzx(ax, word_ptr(rcx)).unwrap();
        // movzx r8d, byte ptr [rdx]
        rt.asm.movzx(r8w, byte_ptr(rdx)).unwrap();

        // jmp ...
        rt.asm.jmp(compare_loop).unwrap();
    }

    rt.asm.set_label(&mut not_equal).unwrap();
    {
        // mov rax, 0x0
        rt.asm.mov(rax, 0x0u64).unwrap();
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut is_equal).unwrap();
    {
        // mov rax, 0x1
        rt.asm.mov(rax, 0x1u64).unwrap();
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // ret
        rt.asm.ret().unwrap();
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\functions\get_proc_address.rs =====

use crate::{
    define_offset,
    runtime::{FnDef, Runtime},
};
use iced_x86::code_asm::{
    eax, ecx, ptr, r12, r13, r14, r15, r15d, rax, rbp, rbx, rcx, rdx, rsp, word_ptr,
};

// void* (const char*, const char*)
pub fn build(rt: &mut Runtime) {
    let mut module_loop = rt.asm.create_label();
    let mut get_exports = rt.asm.create_label();
    let mut export_loop = rt.asm.create_label();
    let mut found = rt.asm.create_label();
    let mut not_found = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    let mut offset = 0;

    define_offset!(number_of_names, offset, 4);
    define_offset!(address_of_names, offset, 8);
    define_offset!(address_of_name_ordinals, offset, 8);
    define_offset!(address_of_functions, offset, 8);

    let stack_size = (offset + 0xF) & !0xF;

    // push rbp
    rt.asm.push(rbp).unwrap();
    // mov rbp, rsp
    rt.asm.mov(rbp, rsp).unwrap();
    // sub rsp, ...
    rt.asm.sub(rsp, stack_size).unwrap();

    // push r12
    rt.asm.push(r12).unwrap();
    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();
    // push r15
    rt.asm.push(r15).unwrap();
    // push rbx
    rt.asm.push(rbx).unwrap();

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();
    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // mov rbx, gs:[0x60] -> PEB *TEB->ProcessEnvironmentBlock
    rt.asm.mov(rbx, ptr(0x60).gs()).unwrap();
    // mov rbx, [rbx + 0x18] -> PEB_LDR_DATA *PEB->Ldr
    rt.asm.mov(rbx, ptr(rbx + 0x18)).unwrap();

    // mov rbx, [rbx + 0x20] -> LDR_DATA_TABLE_ENTRY *PEB->Ldr->InMemoryOrderModuleList.Flink
    rt.asm.mov(rbx, ptr(rbx + 0x20)).unwrap();
    // mov r14, rbx
    rt.asm.mov(r14, rbx).unwrap();

    // module_loop:
    rt.asm.set_label(&mut module_loop).unwrap();
    {
        // lea rcx, [rbx + 0x48] -> UNICODE_STRING *LDR_DATA_TABLE_ENTRY->BaseDllName
        rt.asm.lea(rcx, ptr(rbx + 0x48)).unwrap();
        // mov rcx, [rcx + 0x8] -> PWSTR *UNICODE_STRING->Buffer
        rt.asm.mov(rcx, ptr(rcx + 0x8)).unwrap();
        // mov rdx, r12
        rt.asm.mov(rdx, r12).unwrap();
        // call ...
        rt.asm
            .call(rt.func_labels[&FnDef::CompareUnicodeToAnsi])
            .unwrap();

        // test rax, rax
        rt.asm.test(rax, rax).unwrap();
        // jnz ...
        rt.asm.jnz(get_exports).unwrap();

        // mov rbx, [rbx] -> LIST_ENTRY *LDR_DATA_TABLE_ENTRY->InMemoryOrderLinks.Flink
        rt.asm.mov(rbx, ptr(rbx)).unwrap();
        // cmp rbx, r14
        rt.asm.cmp(rbx, r14).unwrap();
        // je ...
        rt.asm.je(not_found).unwrap();

        // jmp ...
        rt.asm.jmp(module_loop).unwrap();
    }

    rt.asm.set_label(&mut get_exports).unwrap();
    {
        // mov rax, [rbx + 0x20] -> VOID *LDR_DATA_TABLE_ENTRY->DllBase
        rt.asm.mov(rax, ptr(rbx + 0x20)).unwrap();
        // mov rbx, rax
        rt.asm.mov(rbx, rax).unwrap();

        // mov ecx, [rax + 0x3C] -> IMAGE_DOS_HEADER->e_lfanew
        rt.asm.mov(ecx, ptr(rax + 0x3C)).unwrap();
        // add rax, rcx -> IMAGE_NT_HEADERS
        rt.asm.add(rax, rcx).unwrap();
        // add rax, 0x18 -> IMAGE_OPTIONAL_HEADER
        rt.asm.add(rax, 0x18).unwrap();
        // add rax, 0x60 -> IMAGE_DATA_DIRECTORY IMAGE_OPTIONAL_HEADER->DataDirectory[0]
        rt.asm.add(rax, 0x70).unwrap();
        // mov ecx, [rax] -> DWORD IMAGE_DATA_DIRECTORY->VirtualAddress
        rt.asm.mov(ecx, ptr(rax)).unwrap();
        // add rcx, rbx -> IMAGE_EXPORT_DIRECTORY
        rt.asm.add(rcx, rbx).unwrap();

        // mov rax, rcx
        rt.asm.mov(rax, rcx).unwrap();

        // mov ecx, [rax + 0x18] -> DWORD IMAGE_EXPORT_DIRECTORY->NumberOfNames
        rt.asm.mov(ecx, ptr(rax + 0x18)).unwrap();
        // mov [rbp - ...], ecx
        rt.asm.mov(ptr(rbp - number_of_names), ecx).unwrap();

        // mov ecx, [rax + 0x20] -> DWORD IMAGE_EXPORT_DIRECTORY->AddressOfNames
        rt.asm.mov(ecx, ptr(rax + 0x20)).unwrap();
        // add rcx, rbx -> IMAGE_EXPORT_DIRECTORY
        rt.asm.add(rcx, rbx).unwrap();
        // mov [rbp - ...], ecx
        rt.asm.mov(ptr(rbp - address_of_names), rcx).unwrap();

        // mov ecx, [rax + 0x24] -> DWORD IMAGE_EXPORT_DIRECTORY->AddressOfNameOrdinals
        rt.asm.mov(ecx, ptr(rax + 0x24)).unwrap();
        // add rcx, rbx
        rt.asm.add(rcx, rbx).unwrap();
        // mov [rbp - ...], rcx
        rt.asm
            .mov(ptr(rbp - address_of_name_ordinals), rcx)
            .unwrap();

        // mov ecx, [rax + 0x1C] -> DWORD IMAGE_EXPORT_DIRECTORY->AddressOfFunctions
        rt.asm.mov(ecx, ptr(rax + 0x1C)).unwrap();
        // add rcx, rbx -> PDWORD AddressOfFunctions VA
        rt.asm.add(rcx, rbx).unwrap();
        // mov [rbp - ...], rcx
        rt.asm.mov(ptr(rbp - address_of_functions), rcx).unwrap();

        // xor r15, r15
        rt.asm.xor(r15, r15).unwrap();

        rt.asm.set_label(&mut export_loop).unwrap();
        {
            // cmp r15d, [rbp - ...]
            rt.asm.cmp(r15d, ptr(rbp - number_of_names)).unwrap();
            // je not_found
            rt.asm.je(not_found).unwrap();

            // mov rax, [rbp - ...]
            rt.asm.mov(rax, ptr(rbp - address_of_names)).unwrap();
            // mov eax, [rax + r15*4]
            rt.asm.mov(eax, ptr(rax + r15 * 4)).unwrap();
            // add rax, rbx
            rt.asm.add(rax, rbx).unwrap();

            // mov rcx, rax
            rt.asm.mov(rcx, rax).unwrap();
            // mov rax, r13
            rt.asm.mov(rdx, r13).unwrap();
            // call ...
            rt.asm.call(rt.func_labels[&FnDef::CompareAnsi]).unwrap();

            // test rax, rax
            rt.asm.test(rax, rax).unwrap();
            // jnz ...
            rt.asm.jnz(found).unwrap();

            // inc r15
            rt.asm.inc(r15).unwrap();
            // jmp ...
            rt.asm.jmp(export_loop).unwrap();
        }
    }

    rt.asm.set_label(&mut found).unwrap();
    {
        // mov rax, [rbp - ...]
        rt.asm
            .mov(rax, ptr(rbp - address_of_name_ordinals))
            .unwrap();
        // movzx rdx, word ptr [rax + r15*2]
        rt.asm.movzx(rdx, word_ptr(rax + r15 * 2)).unwrap();

        // mov rax, [rbp - ...]
        rt.asm.mov(rax, ptr(rbp - address_of_functions)).unwrap();
        // mov eax, [rax + rdx*4]
        rt.asm.mov(eax, ptr(rax + rdx * 4)).unwrap();
        // add rax, rbx
        rt.asm.add(rax, rbx).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut not_found).unwrap();
    {
        // xor rax, rax
        rt.asm.xor(rax, rax).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // pop rbx
        rt.asm.pop(rbx).unwrap();
        // pop r15
        rt.asm.pop(r15).unwrap();
        // pop r14
        rt.asm.pop(r14).unwrap();
        // pop r13
        rt.asm.pop(r13).unwrap();
        // pop r12
        rt.asm.pop(r12).unwrap();

        // mov rsp, rbp
        rt.asm.mov(rsp, rbp).unwrap();
        // pop rbp
        rt.asm.pop(rbp).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\functions\mod.rs =====

pub mod compare_ansi;
pub mod compare_unicode_to_ansi;
pub mod get_proc_address;

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\lib.rs =====

pub mod functions;
pub mod mapper;
pub mod runtime;
pub mod vm;

macro_rules! define_offset {
    ($name:ident, $offset:expr, $size:expr) => {
        $offset += $size;
        let $name = $offset;
    };
}

pub(crate) use define_offset;

pub const VM_STACK_SIZE: u64 = 0x100;

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\mapper.rs =====

use std::{
    any::{Any, TypeId},
    collections::HashMap,
};

use rand::seq::SliceRandom as _;

pub trait Mappable: Copy + Eq + std::hash::Hash
where
    Self: 'static,
{
    const VARIANTS: &'static [Self];
    const COUNT: usize = Self::VARIANTS.len();
}

struct Mapped<T> {
    map: HashMap<T, u8>,
    variants: Vec<T>,
}

impl<T: Mappable> Mapped<T> {
    pub fn new() -> Self {
        let mut variants = T::VARIANTS.to_vec();
        variants.shuffle(&mut rand::thread_rng());

        let mut map = HashMap::with_capacity(variants.len());

        for (i, v) in variants.iter().enumerate() {
            map.insert(*v, i as u8);
        }

        Self { map, variants }
    }

    #[inline]
    pub fn index(&self, v: T) -> u8 {
        self.map[&v]
    }

    #[inline]
    pub fn from_index(&self, i: u8) -> T {
        self.variants[i as usize]
    }

    #[inline]
    pub fn count(&self) -> usize {
        self.variants.len()
    }
}

pub struct Mapper {
    maps: HashMap<TypeId, Box<dyn Any>>,
}

impl Mapper {
    pub fn new() -> Self {
        Self {
            maps: HashMap::new(),
        }
    }

    fn get<T: Mappable>(&mut self) -> &Mapped<T> {
        let id = TypeId::of::<T>();

        if !self.maps.contains_key(&id) {
            let mapped = Mapped::<T>::new();
            self.maps.insert(id, Box::new(mapped));
        }

        self.maps
            .get(&id)
            .unwrap()
            .downcast_ref::<Mapped<T>>()
            .unwrap()
    }

    #[inline]
    pub fn index<T: Mappable>(&mut self, v: T) -> u8 {
        self.get::<T>().index(v)
    }

    #[inline]
    pub fn from_index<T: Mappable>(&mut self, i: u8) -> T {
        self.get::<T>().from_index(i)
    }

    #[inline]
    pub fn count<T: Mappable>(&mut self) -> usize {
        self.get::<T>().count()
    }
}

macro_rules! mapped {
    ($ty:ident { $($v:ident),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
        pub enum $ty {
            #[doc(hidden)]
            $($v { _sealed: () }),+
        }

        #[allow(non_upper_case_globals)]
        impl $ty {
            $(
                pub const $v: Self = Self::$v { _sealed: () };
            )+
        }

        impl crate::mapper::Mappable for $ty {
            const VARIANTS: &'static [Self] = &[
                $(Self::$v),+
            ];
        }
    };
}
pub(crate) use mapped;

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\runtime.rs =====

use std::collections::HashMap;

use iced_x86::{
    code_asm::{ptr, rcx, rdx, CodeAssembler, CodeLabel},
    BlockEncoderOptions, Decoder, DecoderOptions, Encoder,
};
use rand::seq::SliceRandom;

use crate::{
    functions,
    mapper::{Mappable, Mapper},
    vm::{
        self,
        bytecode::{VMOp, VMReg},
    },
};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[derive(Copy, Clone, PartialEq, Eq, Hash, EnumIter)]
pub enum FnDef {
    /* VM */
    VmGInit,
    VmTInit,
    VmEntry,
    VmExit,
    VmCrypt,
    VmDispatch,
    VmCleanup,
    /* VM UTILS */
    ComputeAddress,
    /* VM HANDLERS */
    VmHandlerPushPopRegs,
    VmHandlerPushImm,
    VmHandlerPushReg,
    VmHandlerPopReg,
    VmHandlerSetRegImm,
    VmHandlerSetRegReg,
    VmHandlerSetRegMem,
    VmHandlerSetMemImm,
    VmHandlerSetMemReg,
    VmHandlerAddSubRegImm,
    VmHandlerAddSubRegMem,
    VmHandlerAddSubRegReg,
    VmHandlerAddSubMemImm,
    VmHandlerAddSubMemReg,
    VmHandlerBranchImm,
    VmHandlerBranchReg,
    VmHandlerBranchMem,
    VmHandlerJcc,
    VmHandlerNop,
    /* VM ARITHMETIC */
    VmArithmeticFlags,
    VmArithmeticAddSub8,
    VmArithmeticAddSub16,
    VmArithmeticAddSub32,
    VmArithmeticAddSub64,
    /* VM VEH */
    VmVehInitialize,
    VmVehHandler,
    /* VM STACK */
    VmStackInitialize,
    /* CORE */
    CompareUnicodeToAnsi,
    CompareAnsi,
    GetProcAddress,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, EnumIter)]
pub enum DataDef {
    VehStart,
    VmHandlers,
    VmGlobalState,
    VmStateTlsIndex,
    VmStackTlsIndex,
    VmCleanupFlsIndex,
    VmTable,
    VmCode,
    VmKeySeed,
    VmKeyMul,
    VmKeyAdd,
    VehEnd,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, EnumIter)]
pub enum BoolDef {
    VmIsLocked,
    VmHasVeh,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, EnumIter)]
pub enum StringDef {
    Ntdll,
    KERNEL32,
    KERNELBASE,
    NtQueryInformationProcess,
    RtlAddVectoredExceptionHandler,
    TlsAlloc,
    RtlFlsAlloc,
    RtlFlsSetValue,
    GetProcessHeap,
    RtlAllocateHeap,
    RtlFreeHeap,
}

enum EmissionTask {
    Function(FnDef, fn(&mut Runtime)),
    Data(DataDef),
    Bool(BoolDef),
    String(StringDef),
}

pub struct Runtime {
    pub asm: CodeAssembler,
    pub func_labels: HashMap<FnDef, CodeLabel>,
    pub data_labels: HashMap<DataDef, CodeLabel>,
    data: HashMap<DataDef, Vec<u8>>,
    pub bool_labels: HashMap<BoolDef, CodeLabel>,
    bools: HashMap<BoolDef, bool>,
    string_labels: HashMap<StringDef, CodeLabel>,
    strings: HashMap<StringDef, Vec<u8>>,
    addresses: HashMap<CodeLabel, u64>,
    fixups: HashMap<CodeLabel, (CodeLabel, u64, Option<usize>)>,
    current_chain: Option<usize>,
    next_chain_id: usize,
    pub mapper: Mapper,
}

impl Runtime {
    pub fn new(bitness: u32) -> Self {
        let mut asm = CodeAssembler::new(bitness).unwrap();

        let mut func_labels = HashMap::new();

        for def in FnDef::iter() {
            func_labels.insert(def, asm.create_label());
        }

        let mut data_labels = HashMap::new();

        for def in DataDef::iter() {
            data_labels.insert(def, asm.create_label());
        }

        let mut bool_labels = HashMap::new();

        for def in BoolDef::iter() {
            bool_labels.insert(def, asm.create_label());
        }

        let mut string_labels = HashMap::new();

        for def in StringDef::iter() {
            string_labels.insert(def, asm.create_label());
        }

        Self {
            asm,
            func_labels,
            data_labels,
            data: HashMap::new(),
            bool_labels,
            bools: HashMap::new(),
            string_labels,
            strings: HashMap::new(),
            addresses: HashMap::new(),
            fixups: HashMap::new(),
            mapper: Mapper::new(),
            current_chain: None,
            next_chain_id: 0,
        }
    }

    pub fn with_chain<F>(&mut self, f: F)
    where
        F: FnOnce(&mut Self),
    {
        self.current_chain = Some(self.next_chain_id);
        self.next_chain_id += 1;

        f(self);

        self.current_chain = None;
    }

    pub fn mark_as_encrypted(&mut self, target: CodeLabel) -> u64 {
        let mut label = self.asm.create_label();
        self.asm.set_label(&mut label).unwrap();
        let key = rand::random::<u64>();
        self.fixups.insert(label, (target, key, self.current_chain));
        key
    }

    fn set_func_label(&mut self, def: FnDef) {
        let label = self.func_labels.get_mut(&def).unwrap();
        self.asm.set_label(label).unwrap();
    }

    fn set_data_label(&mut self, def: DataDef) {
        let label = self.data_labels.get_mut(&def).unwrap();
        self.asm.set_label(label).unwrap();
    }

    fn set_bool_label(&mut self, def: BoolDef) {
        let label = self.bool_labels.get_mut(&def).unwrap();
        self.asm.set_label(label).unwrap();
    }

    fn set_string_label(&mut self, def: StringDef) {
        let label = self.string_labels.get_mut(&def).unwrap();
        self.asm.set_label(label).unwrap();
    }

    pub fn lookup(&self, label: CodeLabel) -> u64 {
        self.addresses[&label]
    }

    pub fn define_data_byte(&mut self, def: DataDef, data: u8) {
        self.data.insert(def, vec![data]);
    }

    pub fn define_data_bytes(&mut self, def: DataDef, data: &[u8]) {
        self.data.insert(def, data.to_vec());
    }

    pub fn define_data_dword(&mut self, def: DataDef, data: u32) {
        self.data.insert(def, data.to_le_bytes().to_vec());
    }

    pub fn define_data_qword(&mut self, def: DataDef, data: u64) {
        self.data.insert(def, data.to_le_bytes().to_vec());
    }

    pub fn define_bool(&mut self, def: BoolDef, value: bool) {
        self.bools.insert(def, value);
    }

    fn define_string(&mut self, def: StringDef, string: &str) {
        let mut bytes = string.as_bytes().to_vec();
        bytes.push(0);
        self.strings.insert(def, bytes);
    }

    pub fn get_proc_address(&mut self, module_name: StringDef, export_name: StringDef) {
        // lea rcx, [...]
        self.asm
            .lea(rcx, ptr(self.string_labels[&module_name]))
            .unwrap();
        // lea rdx, [...]
        self.asm
            .lea(rdx, ptr(self.string_labels[&export_name]))
            .unwrap();
        // call ...
        self.asm
            .call(self.func_labels[&FnDef::GetProcAddress])
            .unwrap();
    }

    pub fn assemble(&mut self, ip: u64) -> Vec<u8> {
        let mut shuffled = Vec::new();

        let functions: Vec<(FnDef, fn(&mut Runtime))> = vec![
            (FnDef::VmGInit, vm::ginit::build),
            (FnDef::VmTInit, vm::tinit::build),
            (FnDef::VmEntry, vm::entry::build),
            (FnDef::VmExit, vm::exit::build),
            (FnDef::VmCrypt, vm::crypt::build),
            (FnDef::VmDispatch, vm::dispatch::build),
            (FnDef::VmCleanup, vm::cleanup::build),
            (FnDef::ComputeAddress, vm::utils::compute_address::build),
            (
                FnDef::VmHandlerPushPopRegs,
                vm::handlers::pushpopregs::build,
            ),
            (FnDef::VmHandlerPushImm, vm::handlers::pushimm::build),
            (FnDef::VmHandlerPushReg, vm::handlers::pushreg::build),
            (FnDef::VmHandlerPopReg, vm::handlers::popreg::build),
            (FnDef::VmHandlerSetRegImm, vm::handlers::setregimm::build),
            (FnDef::VmHandlerSetRegReg, vm::handlers::setregreg::build),
            (FnDef::VmHandlerSetRegMem, vm::handlers::setregmem::build),
            (FnDef::VmHandlerSetMemImm, vm::handlers::setmemimm::build),
            (FnDef::VmHandlerSetMemReg, vm::handlers::setmemreg::build),
            (
                FnDef::VmHandlerAddSubRegImm,
                vm::handlers::arithmetic::addsubregimm::build,
            ),
            (
                FnDef::VmHandlerAddSubRegMem,
                vm::handlers::arithmetic::addsubregmem::build,
            ),
            (
                FnDef::VmHandlerAddSubRegReg,
                vm::handlers::arithmetic::addsubregreg::build,
            ),
            (
                FnDef::VmHandlerAddSubMemImm,
                vm::handlers::arithmetic::addsubmemimm::build,
            ),
            (
                FnDef::VmHandlerAddSubMemReg,
                vm::handlers::arithmetic::addsubmemreg::build,
            ),
            (FnDef::VmHandlerBranchImm, vm::handlers::branchimm::build),
            (FnDef::VmHandlerBranchReg, vm::handlers::branchreg::build),
            (FnDef::VmHandlerBranchMem, vm::handlers::branchmem::build),
            (FnDef::VmHandlerJcc, vm::handlers::jcc::build),
            (FnDef::VmHandlerNop, vm::handlers::nop::build),
            (
                FnDef::VmArithmeticFlags,
                vm::handlers::arithmetic::flags::build,
            ),
            (
                FnDef::VmArithmeticAddSub8,
                vm::handlers::arithmetic::addsub8::build,
            ),
            (
                FnDef::VmArithmeticAddSub16,
                vm::handlers::arithmetic::addsub16::build,
            ),
            (
                FnDef::VmArithmeticAddSub32,
                vm::handlers::arithmetic::addsub32::build,
            ),
            (
                FnDef::VmArithmeticAddSub64,
                vm::handlers::arithmetic::addsub64::build,
            ),
            (FnDef::VmVehInitialize, vm::veh::initialize),
            (
                FnDef::CompareUnicodeToAnsi,
                functions::compare_unicode_to_ansi::build,
            ),
            (FnDef::CompareAnsi, functions::compare_ansi::build),
            (FnDef::GetProcAddress, functions::get_proc_address::build),
        ];

        self.define_data_byte(DataDef::VehStart, 0x90);
        self.define_data_byte(DataDef::VehEnd, 0x90);

        self.define_data_bytes(DataDef::VmHandlers, &[0u8; VMOp::COUNT * 8]);
        self.define_data_bytes(DataDef::VmGlobalState, &[0u8; VMReg::COUNT * 8]);

        self.define_data_dword(DataDef::VmStateTlsIndex, 0);
        self.define_data_dword(DataDef::VmStackTlsIndex, 0);
        self.define_data_dword(DataDef::VmCleanupFlsIndex, 0);

        self.define_bool(BoolDef::VmIsLocked, false);
        self.define_bool(BoolDef::VmHasVeh, false);

        self.define_string(StringDef::Ntdll, "ntdll.dll");
        self.define_string(StringDef::KERNEL32, "KERNEL32.DLL");
        self.define_string(StringDef::KERNELBASE, "KERNELBASE.DLL");
        self.define_string(
            StringDef::NtQueryInformationProcess,
            "NtQueryInformationProcess",
        );
        self.define_string(
            StringDef::RtlAddVectoredExceptionHandler,
            "RtlAddVectoredExceptionHandler",
        );
        self.define_string(StringDef::TlsAlloc, "TlsAlloc");
        self.define_string(StringDef::RtlFlsAlloc, "RtlFlsAlloc");
        self.define_string(StringDef::RtlFlsSetValue, "RtlFlsSetValue");
        self.define_string(StringDef::GetProcessHeap, "GetProcessHeap");
        self.define_string(StringDef::RtlAllocateHeap, "RtlAllocateHeap");
        self.define_string(StringDef::RtlFreeHeap, "RtlFreeHeap");

        for (def, builder) in functions {
            shuffled.push(EmissionTask::Function(def, builder));
        }

        for def in DataDef::iter() {
            if def == DataDef::VehStart || def == DataDef::VehEnd {
                continue;
            }

            if self.data.contains_key(&def) {
                shuffled.push(EmissionTask::Data(def));
            }
        }

        for def in BoolDef::iter() {
            if self.bools.contains_key(&def) {
                shuffled.push(EmissionTask::Bool(def));
            }
        }

        for def in StringDef::iter() {
            if self.strings.contains_key(&def) {
                shuffled.push(EmissionTask::String(def));
            }
        }

        let mut rng = rand::thread_rng();
        shuffled.shuffle(&mut rng);

        let mut tasks = Vec::new();
        tasks.push(EmissionTask::Function(
            FnDef::VmVehHandler,
            vm::veh::handler,
        ));
        tasks.push(EmissionTask::Data(DataDef::VehStart));
        tasks.extend(shuffled);
        tasks.push(EmissionTask::Data(DataDef::VehEnd));

        for task in tasks {
            match task {
                EmissionTask::Function(def, builder) => {
                    self.set_func_label(def);
                    builder(self);
                }
                EmissionTask::Data(def) => {
                    self.set_data_label(def);
                    self.asm.db(&self.data[&def]).unwrap();
                }
                EmissionTask::Bool(def) => {
                    self.set_bool_label(def);
                    self.asm.db(&[self.bools[&def] as u8]).unwrap();
                }
                EmissionTask::String(def) => {
                    self.set_string_label(def);
                    self.asm.db(&self.strings[&def]).unwrap();
                }
            }
        }

        let result = self
            .asm
            .assemble_options(ip, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
            .unwrap();

        let labels = self
            .func_labels
            .values()
            .chain(self.data_labels.values())
            .chain(self.bool_labels.values())
            .chain(self.string_labels.values());

        for label in labels {
            if let Ok(rva) = result.label_ip(label) {
                self.addresses.insert(*label, rva);
            }
        }

        let mut code = result.inner.code_buffer.clone();

        let mut states = HashMap::new();

        let mut fixups = self
            .fixups
            .iter()
            .collect::<Vec<(&CodeLabel, &(CodeLabel, u64, Option<usize>))>>();
        fixups.sort_by_key(|(src, _)| result.label_ip(src).unwrap());

        for (&src, &(target, key, chain)) in fixups {
            let rva = result.label_ip(&src).unwrap();
            let offset = (rva - ip) as usize;

            let mut decoder = Decoder::with_ip(
                self.asm.bitness(),
                &code[offset..],
                rva,
                DecoderOptions::NONE,
            );
            let instruction = decoder.decode();

            let dst = self.addresses[&target];

            let encrypted = if let Some(id) = chain {
                let previous = *states.get(&id).unwrap_or(&0);
                states.insert(id, dst);
                dst ^ key ^ previous
            } else {
                dst ^ key
            };

            let mut encoder = Encoder::new(self.asm.bitness());
            encoder.encode(&instruction, rva).unwrap();

            let mut encoded = encoder.take_buffer();
            let constants = encoder.get_constant_offsets();

            assert!(constants.has_immediate());

            let imm_offset = constants.immediate_offset();
            let imm_size = constants.immediate_size();

            encoded[imm_offset..imm_offset + imm_size]
                .copy_from_slice(&encrypted.to_le_bytes()[..imm_size]);

            code[offset..offset + instruction.len()].copy_from_slice(&encoded);
        }

        code
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\bytecode.rs =====

use iced_x86::{Code, Instruction, Mnemonic, OpKind, Register};

use crate::mapper::{mapped, Mapper};

mapped! {
    VMOp {
        PushPopRegs,
        PopRegs,
        PushImm,
        PushReg,
        PopReg,
        SetRegImm,
        SetRegReg,
        SetRegMem,
        SetMemImm,
        SetMemReg,
        AddSubRegImm,
        AddSubRegReg,
        AddSubRegMem,
        AddSubMemImm,
        AddSubMemReg,
        BranchImm,
        BranchReg,
        BranchMem,
        Jcc,
        Nop,
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VMFlag {
    Carry = 0,      // CF
    Parity = 2,     // PF
    Auxiliary = 4,  // AF
    Zero = 6,       // ZF
    Sign = 7,       // SF
    Trap = 8,       // TF
    Interrupt = 9,  // IF
    Direction = 10, // DF
    Overflow = 11,  // OF
}

mapped! {
    VMTest {
        CMP,
        EQ,
        NEQ,
    }
}

mapped! {
    VMLogic {
        AND,
        OR,
    }
}

mapped! {
    VMReg {
        None,
        Rax,
        Rcx,
        Rdx,
        Rbx,
        Rsp,
        Rbp,
        Rsi,
        Rdi,
        R8,
        R9,
        R10,
        R11,
        R12,
        R13,
        R14,
        R15,
        Vra, // Native Exit
        Flags,
        Vea, // Native Entry
        Vbp, // Block Pointer
        Vbl, // Block Length
        VB, // Image Base
        Vsk, // System Key
        V0, // Scratch 0
        V1, // Scratch 1
    }
}

impl From<Register> for VMReg {
    fn from(reg: Register) -> Self {
        match reg {
            Register::None => Self::None,
            Register::RAX | Register::EAX | Register::AX | Register::AL | Register::AH => Self::Rax,
            Register::RCX | Register::ECX | Register::CX | Register::CL | Register::CH => Self::Rcx,
            Register::RDX | Register::EDX | Register::DX | Register::DL | Register::DH => Self::Rdx,
            Register::RBX | Register::EBX | Register::BX | Register::BL | Register::BH => Self::Rbx,
            Register::RSP | Register::ESP | Register::SP | Register::SPL => Self::Rsp,
            Register::RBP | Register::EBP | Register::BP | Register::BPL => Self::Rbp,
            Register::RSI | Register::ESI | Register::SI | Register::SIL => Self::Rsi,
            Register::RDI | Register::EDI | Register::DI | Register::DIL => Self::Rdi,
            Register::R8 | Register::R8D | Register::R8W | Register::R8L => Self::R8,
            Register::R9 | Register::R9D | Register::R9W | Register::R9L => Self::R9,
            Register::R10 | Register::R10D | Register::R10W | Register::R10L => Self::R10,
            Register::R11 | Register::R11D | Register::R11W | Register::R11L => Self::R11,
            Register::R12 | Register::R12D | Register::R12W | Register::R12L => Self::R12,
            Register::R13 | Register::R13D | Register::R13W | Register::R13L => Self::R13,
            Register::R14 | Register::R14D | Register::R14W | Register::R14L => Self::R14,
            Register::R15 | Register::R15D | Register::R15W | Register::R15L => Self::R15,
            Register::RIP => Self::VB,
            _ => panic!("unsupported register: {reg:?}"),
        }
    }
}

mapped! {
    VMBits {
        Lower8,
        Higher8,
        Lower16,
        Lower32,
        Lower64,
    }
}

impl From<Register> for VMBits {
    fn from(reg: Register) -> Self {
        match reg {
            reg if (reg >= Register::AL && reg <= Register::BL)
                || (reg >= Register::SPL && reg <= Register::R15L) =>
            {
                Self::Lower8
            }
            reg if (reg >= Register::AH && reg <= Register::BH) => Self::Higher8,
            reg if (reg >= Register::AX && reg <= Register::R15W) => Self::Lower16,
            reg if (reg >= Register::EAX && reg <= Register::R15D) || reg == Register::EIP => {
                Self::Lower32
            }
            reg if (reg >= Register::RAX && reg <= Register::R15) || reg == Register::RIP => {
                Self::Lower64
            }
            _ => panic!("unsupported register: {reg:?}"),
        }
    }
}

mapped! {
    VMSeg {
        None,
        Gs,
    }
}

impl From<Register> for VMSeg {
    fn from(reg: Register) -> Self {
        match reg {
            Register::None => Self::None,
            Register::GS => Self::Gs,
            _ => panic!("unsupported segment: {reg:?}"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VMMem {
    pub base: VMReg,
    pub index: VMReg,
    pub scale: u8,
    pub displacement: i32,
    pub seg: VMSeg,
}

impl VMMem {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(mapper.index(self.base));
        bytes.push(mapper.index(self.index));
        bytes.push(self.scale);
        bytes.extend_from_slice(&self.displacement.to_le_bytes());
        bytes.push(mapper.index(self.seg));
        bytes
    }
}

impl From<&Instruction> for VMMem {
    fn from(instruction: &Instruction) -> Self {
        let base = VMReg::from(instruction.memory_base());
        let index = VMReg::from(instruction.memory_index());
        let scale = instruction.memory_index_scale() as u8;
        let displacement = (instruction.memory_displacement64() as i64)
            .try_into()
            .unwrap();
        let seg = VMSeg::from(instruction.segment_prefix());

        Self {
            base,
            index,
            scale,
            displacement,
            seg,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VMCond {
    pub cmp: VMTest,
    pub lhs: u8,
    pub rhs: u8,
}

impl VMCond {
    pub fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        vec![mapper.index(self.cmp), self.lhs, self.rhs]
    }
}

pub enum VMCmd<'a> {
    PushPopRegs {
        vop: VMOp,
        pop: bool,
        seq: Vec<u8>,
    },
    PushImm {
        vop: VMOp,
        src: &'a [u8],
    },
    PushReg {
        vop: VMOp,
        src: VMReg,
    },
    PopReg {
        vop: VMOp,
        dst: VMReg,
    },
    SetRegImm {
        vop: VMOp,
        dbits: VMBits,
        dst: VMReg,
        src: &'a [u8],
    },
    SetRegReg {
        vop: VMOp,
        dbits: VMBits,
        dst: VMReg,
        sbits: VMBits,
        src: VMReg,
    },
    SetRegMem {
        vop: VMOp,
        dbits: VMBits,
        load: bool,
        dst: VMReg,
        src: VMMem,
    },
    SetMemImm {
        vop: VMOp,
        dst: VMMem,
        src: &'a [u8],
    },
    SetMemReg {
        vop: VMOp,
        sbits: VMBits,
        dst: VMMem,
        src: VMReg,
    },
    AddSubRegImm {
        vop: VMOp,
        dbits: VMBits,
        dst: VMReg,
        sub: bool,
        store: bool,
        src: &'a [u8],
    },
    AddSubRegReg {
        vop: VMOp,
        dbits: VMBits,
        dst: VMReg,
        sbits: VMBits,
        src: VMReg,
        sub: bool,
        store: bool,
    },
    AddSubRegMem {
        vop: VMOp,
        src: VMMem,
        sub: bool,
        store: bool,
        dbits: VMBits,
        dst: VMReg,
    },
    AddSubMemImm {
        vop: VMOp,
        dst: VMMem,
        sub: bool,
        store: bool,
        src: &'a [u8],
    },
    AddSubMemReg {
        vop: VMOp,
        dst: VMMem,
        sub: bool,
        store: bool,
        sbits: VMBits,
        src: VMReg,
    },
    BranchImm {
        vop: VMOp,
        ret: bool,
        dst: u32,
    },
    BranchReg {
        vop: VMOp,
        ret: bool,
        dst: VMReg,
    },
    BranchMem {
        vop: VMOp,
        ret: bool,
        dst: VMMem,
    },
    Jcc {
        vop: VMOp,
        logic: VMLogic,
        conds: Vec<VMCond>,
        dst: u32,
    },
    Nop {
        vop: VMOp,
    },
}

impl<'a> VMCmd<'a> {
    pub fn encode(&self, mapper: &mut Mapper) -> Vec<u8> {
        match self {
            Self::PushPopRegs { vop, pop, seq } => {
                let mut bytes = vec![mapper.index(*vop)];
                bytes.push(*pop as u8);
                bytes.push(seq.len() as u8);
                bytes.extend_from_slice(seq);
                bytes
            }
            Self::PushImm { vop, src } => {
                let mut bytes = vec![mapper.index(*vop)];
                bytes.push(src.len() as u8);
                bytes.extend_from_slice(src);
                bytes
            }
            Self::PushReg { vop, src } => {
                let bytes = vec![mapper.index(*vop), mapper.index(*src)];
                bytes
            }
            Self::PopReg { vop, dst } => {
                let bytes = vec![mapper.index(*vop), mapper.index(*dst)];
                bytes
            }
            Self::SetRegImm {
                vop,
                dbits,
                dst,
                src,
            } => {
                let mut bytes = vec![mapper.index(*vop), mapper.index(*dbits), mapper.index(*dst)];
                bytes.extend_from_slice(src);
                bytes
            }
            Self::SetRegReg {
                vop,
                dbits,
                dst,
                sbits,
                src,
            } => {
                let bytes = vec![
                    mapper.index(*vop),
                    mapper.index(*dbits),
                    mapper.index(*dst),
                    mapper.index(*sbits),
                    mapper.index(*src),
                ];
                bytes
            }
            Self::SetRegMem {
                vop,
                dbits,
                load,
                dst,
                src,
            } => {
                let mut bytes = vec![
                    mapper.index(*vop),
                    mapper.index(*dbits),
                    *load as u8,
                    mapper.index(*dst),
                ];
                bytes.extend_from_slice(&src.encode(mapper));
                bytes
            }
            Self::SetMemImm { vop, dst, src } => {
                let mut bytes = vec![mapper.index(*vop)];
                bytes.extend_from_slice(&dst.encode(mapper));
                bytes.push(src.len() as u8);
                bytes.extend_from_slice(src);
                bytes
            }
            Self::SetMemReg {
                vop,
                sbits,
                dst,
                src,
            } => {
                let mut bytes = vec![mapper.index(*vop), mapper.index(*sbits)];
                bytes.extend_from_slice(&dst.encode(mapper));
                bytes.push(mapper.index(*src));
                bytes
            }
            Self::AddSubRegImm {
                vop,
                dbits,
                dst,
                sub,
                store,
                src,
            } => {
                let mut bytes = vec![
                    mapper.index(*vop),
                    mapper.index(*dbits),
                    mapper.index(*dst),
                    *sub as u8,
                    *store as u8,
                ];
                bytes.extend_from_slice(src);
                bytes
            }
            Self::AddSubRegReg {
                vop,
                dbits,
                dst,
                sbits,
                src,
                sub,
                store,
            } => {
                let bytes = vec![
                    mapper.index(*vop),
                    mapper.index(*dbits),
                    mapper.index(*dst),
                    mapper.index(*sbits),
                    mapper.index(*src),
                    *sub as u8,
                    *store as u8,
                ];
                bytes
            }
            Self::AddSubRegMem {
                vop,
                src,
                sub,
                store,
                dbits,
                dst,
            } => {
                let mut bytes = vec![mapper.index(*vop)];
                bytes.extend_from_slice(&src.encode(mapper));
                bytes.push(*sub as u8);
                bytes.push(*store as u8);
                bytes.push(mapper.index(*dbits));
                bytes.push(mapper.index(*dst));
                bytes
            }
            Self::AddSubMemImm {
                vop,
                dst,
                sub,
                store,
                src,
            } => {
                let mut bytes = vec![mapper.index(*vop)];
                bytes.extend_from_slice(&dst.encode(mapper));
                bytes.push(*sub as u8);
                bytes.push(*store as u8);
                bytes.push(src.len() as u8);
                bytes.extend_from_slice(src);
                bytes
            }
            Self::AddSubMemReg {
                vop,
                dst,
                sub,
                store,
                sbits,
                src,
            } => {
                let mut bytes = vec![mapper.index(*vop)];
                bytes.extend_from_slice(&dst.encode(mapper));
                bytes.push(*sub as u8);
                bytes.push(*store as u8);
                bytes.push(mapper.index(*sbits));
                bytes.push(mapper.index(*src));
                bytes
            }
            Self::BranchImm { vop, ret, dst } => {
                let mut bytes = vec![mapper.index(*vop), *ret as u8];
                bytes.extend_from_slice(&dst.to_le_bytes());
                bytes
            }
            Self::BranchReg { vop, ret, dst } => {
                vec![mapper.index(*vop), *ret as u8, mapper.index(*dst)]
            }
            Self::BranchMem { vop, ret, dst } => {
                let mut bytes = vec![mapper.index(*vop), *ret as u8];
                bytes.extend_from_slice(&dst.encode(mapper));
                bytes
            }
            Self::Jcc {
                vop,
                logic,
                conds,
                dst,
            } => {
                let mut bytes = vec![mapper.index(*vop), mapper.index(*logic), conds.len() as u8];

                for op in conds {
                    bytes.extend_from_slice(&op.encode(mapper));
                }
                bytes.extend_from_slice(&dst.to_le_bytes());
                bytes
            }
            Self::Nop { vop } => {
                let bytes = vec![mapper.index(*vop)];
                bytes
            }
        }
    }
}

pub fn convert(mapper: &mut Mapper, instructions: &[Instruction]) -> Option<Vec<u8>> {
    let mut vinstructions = Vec::new();

    let mut i = 0;

    while i < instructions.len() {
        let instruction = &instructions[i];
        let code = instruction.code();

        if code == Code::Push_r64 || code == Code::Pop_r64 {
            let mut seq = Vec::new();

            let mut j = i;

            while j < instructions.len() && instructions[j].code() == code {
                let vreg = VMReg::from(instructions[j].op0_register());
                let idx = mapper.index(vreg);
                seq.push(idx);
                j += 1;
            }

            if seq.len() >= 2 {
                let pop = instruction.mnemonic() == Mnemonic::Pop;

                vinstructions.extend_from_slice(
                    &VMCmd::PushPopRegs {
                        vop: VMOp::PushPopRegs,
                        pop,
                        seq,
                    }
                    .encode(mapper),
                );

                i = j;
                continue;
            }
        }

        let bytecode = match code {
            Code::Pushq_imm8 => {
                let src = instruction.immediate8();
                VMCmd::PushImm {
                    vop: VMOp::PushImm,
                    src: &src.to_le_bytes(),
                }
            }
            Code::Push_imm16 => {
                let src = instruction.immediate16();
                VMCmd::PushImm {
                    vop: VMOp::PushImm,
                    src: &src.to_le_bytes(),
                }
            }
            Code::Pushq_imm32 => {
                let src = instruction.immediate32();
                VMCmd::PushImm {
                    vop: VMOp::PushImm,
                    src: &src.to_le_bytes(),
                }
            }
            Code::Push_r64 => {
                let reg = instruction.op0_register();
                let src = VMReg::from(reg);
                VMCmd::PushReg {
                    vop: VMOp::PushReg,
                    src,
                }
            }
            Code::Pop_r64 => {
                let reg = instruction.op0_register();
                let dst = VMReg::from(reg);
                VMCmd::PopReg {
                    vop: VMOp::PopReg,
                    dst,
                }
            }
            Code::Mov_r8_imm8 => {
                let reg = instruction.op0_register();
                let bits = VMBits::from(reg);
                let dst = VMReg::from(reg);
                let src = instruction.immediate8();
                VMCmd::SetRegImm {
                    vop: VMOp::SetRegImm,
                    dbits: bits,
                    dst,
                    src: &src.to_le_bytes(),
                }
            }
            Code::Mov_r16_imm16 => {
                let reg = instruction.op0_register();
                let dst = VMReg::from(reg);
                let src = instruction.immediate16();
                VMCmd::SetRegImm {
                    vop: VMOp::SetRegImm,
                    dbits: VMBits::Lower16,
                    dst,
                    src: &src.to_le_bytes(),
                }
            }
            Code::Mov_r32_imm32 => {
                let reg = instruction.op0_register();
                let dst = VMReg::from(reg);
                let src = instruction.immediate32();
                VMCmd::SetRegImm {
                    vop: VMOp::SetRegImm,
                    dbits: VMBits::Lower32,
                    dst,
                    src: &src.to_le_bytes(),
                }
            }
            Code::Mov_r64_imm64 => {
                let reg = instruction.op0_register();
                let dst = VMReg::from(reg);
                let src = instruction.immediate64();
                VMCmd::SetRegImm {
                    vop: VMOp::SetRegImm,
                    dbits: VMBits::Lower64,
                    dst,
                    src: &src.to_le_bytes(),
                }
            }
            Code::Mov_r64_rm64 | Code::Mov_r32_rm32 | Code::Mov_r16_rm16 | Code::Mov_r8_rm8 => {
                let dreg = instruction.op0_register();
                let dbits = VMBits::from(dreg);
                let dst = VMReg::from(dreg);

                match instruction.op1_kind() {
                    OpKind::Register => {
                        let sreg = instruction.op1_register();
                        let sbits = VMBits::from(sreg);
                        let src = VMReg::from(sreg);
                        VMCmd::SetRegReg {
                            vop: VMOp::SetRegReg,
                            dbits,
                            dst,
                            sbits,
                            src,
                        }
                    }
                    OpKind::Memory => {
                        let src = VMMem::from(instruction);
                        VMCmd::SetRegMem {
                            vop: VMOp::SetRegMem,
                            dbits,
                            load: true,
                            dst,
                            src,
                        }
                    }
                    _ => return None,
                }
            }
            Code::Mov_rm64_r64 | Code::Mov_rm32_r32 | Code::Mov_rm16_r16 | Code::Mov_rm8_r8 => {
                let sreg = instruction.op1_register();
                let sbits = VMBits::from(sreg);
                let src = VMReg::from(sreg);

                match instruction.op0_kind() {
                    OpKind::Register => {
                        let dreg = instruction.op0_register();
                        let dbits = VMBits::from(dreg);
                        let dst = VMReg::from(dreg);
                        VMCmd::SetRegReg {
                            vop: VMOp::SetRegReg,
                            dbits,
                            dst,
                            sbits,
                            src,
                        }
                    }
                    OpKind::Memory => {
                        let dst = VMMem::from(instruction);
                        VMCmd::SetMemReg {
                            vop: VMOp::SetMemReg,
                            sbits,
                            dst,
                            src,
                        }
                    }
                    _ => return None,
                }
            }
            Code::Mov_rm64_imm32
            | Code::Mov_rm32_imm32
            | Code::Mov_rm16_imm16
            | Code::Mov_rm8_imm8 => {
                let (src, size) = match instruction.code() {
                    Code::Mov_rm8_imm8 => (instruction.immediate8() as i64, 1),
                    Code::Mov_rm16_imm16 => (instruction.immediate16() as i64, 2),
                    Code::Mov_rm32_imm32 => (instruction.immediate32() as i64, 4),
                    Code::Mov_rm64_imm32 => (instruction.immediate32to64() as i64, 8),
                    _ => unreachable!(),
                };

                match instruction.op0_kind() {
                    OpKind::Register => {
                        let reg = instruction.op0_register();
                        let bits = VMBits::from(reg);
                        let dst = VMReg::from(reg);
                        VMCmd::SetRegImm {
                            vop: VMOp::SetRegImm,
                            dbits: bits,
                            dst,
                            src: &src.to_le_bytes()[..size],
                        }
                    }
                    OpKind::Memory => {
                        let dst = VMMem::from(instruction);
                        VMCmd::SetMemImm {
                            vop: VMOp::SetMemImm,
                            dst,
                            src: &src.to_le_bytes()[..size],
                        }
                    }
                    _ => return None,
                }
            }
            Code::Add_rm8_imm8
            | Code::Add_rm16_imm8
            | Code::Add_rm32_imm8
            | Code::Add_rm64_imm8
            | Code::Sub_rm8_imm8
            | Code::Sub_rm16_imm8
            | Code::Sub_rm32_imm8
            | Code::Sub_rm64_imm8
            | Code::Cmp_rm8_imm8
            | Code::Cmp_rm16_imm8
            | Code::Cmp_rm32_imm8
            | Code::Cmp_rm64_imm8 => {
                let sub = matches!(instruction.mnemonic(), Mnemonic::Sub | Mnemonic::Cmp);
                let store = matches!(instruction.mnemonic(), Mnemonic::Add | Mnemonic::Sub);

                let (src, size) = match instruction.op1_kind() {
                    OpKind::Immediate8 => (instruction.immediate8() as i64, 1),
                    OpKind::Immediate8to16 => (instruction.immediate8to16() as i64, 2),
                    OpKind::Immediate8to32 => (instruction.immediate8to32() as i64, 4),
                    OpKind::Immediate8to64 => (instruction.immediate8to64() as i64, 8),
                    _ => unreachable!(),
                };

                match instruction.op0_kind() {
                    OpKind::Register => {
                        let dreg = instruction.op0_register();
                        let dst = VMReg::from(dreg);
                        let dbits = VMBits::from(dreg);
                        VMCmd::AddSubRegImm {
                            vop: VMOp::AddSubRegImm,
                            dbits,
                            dst,
                            sub,
                            store,
                            src: &src.to_le_bytes()[..size],
                        }
                    }
                    OpKind::Memory => {
                        let dst = VMMem::from(instruction);
                        VMCmd::AddSubMemImm {
                            vop: VMOp::AddSubMemImm,
                            dst,
                            sub,
                            store,
                            src: &src.to_le_bytes()[..size],
                        }
                    }
                    _ => return None,
                }
            }
            Code::Add_rm16_imm16 | Code::Sub_rm16_imm16 | Code::Cmp_rm16_imm16 => {
                let sub = matches!(instruction.mnemonic(), Mnemonic::Sub | Mnemonic::Cmp);
                let store = matches!(instruction.mnemonic(), Mnemonic::Add | Mnemonic::Sub);

                let src = instruction.immediate16();

                match instruction.op0_kind() {
                    OpKind::Register => {
                        let reg = instruction.op0_register();
                        let dst = VMReg::from(reg);
                        let bits = VMBits::from(reg);
                        VMCmd::AddSubRegImm {
                            vop: VMOp::AddSubRegImm,
                            dbits: bits,
                            dst,
                            sub,
                            store,
                            src: &src.to_le_bytes(),
                        }
                    }
                    OpKind::Memory => {
                        let dst = VMMem::from(instruction);
                        VMCmd::AddSubMemImm {
                            vop: VMOp::AddSubMemImm,
                            dst,
                            sub,
                            store,
                            src: &src.to_le_bytes(),
                        }
                    }
                    _ => return None,
                }
            }
            Code::Add_rm64_imm32
            | Code::Add_rm32_imm32
            | Code::Sub_rm64_imm32
            | Code::Sub_rm32_imm32
            | Code::Cmp_rm64_imm32
            | Code::Cmp_rm32_imm32 => {
                let sub = matches!(instruction.mnemonic(), Mnemonic::Sub | Mnemonic::Cmp);
                let store = matches!(instruction.mnemonic(), Mnemonic::Add | Mnemonic::Sub);

                let (src, size) = match instruction.op1_kind() {
                    OpKind::Immediate32 => (instruction.immediate32() as i64, 4),
                    OpKind::Immediate32to64 => (instruction.immediate32to64() as i64, 8),
                    _ => unreachable!(),
                };

                match instruction.op0_kind() {
                    OpKind::Register => {
                        let reg = instruction.op0_register();
                        let dst = VMReg::from(reg);
                        let bits = VMBits::from(reg);
                        VMCmd::AddSubRegImm {
                            vop: VMOp::AddSubRegImm,
                            dbits: bits,
                            dst,
                            sub,
                            store,
                            src: &src.to_le_bytes()[..size],
                        }
                    }
                    OpKind::Memory => {
                        let dst = VMMem::from(instruction);
                        VMCmd::AddSubMemImm {
                            vop: VMOp::AddSubMemImm,
                            dst,
                            sub,
                            store,
                            src: &src.to_le_bytes()[..size],
                        }
                    }
                    _ => return None,
                }
            }
            Code::Add_r64_rm64
            | Code::Add_r32_rm32
            | Code::Add_r16_rm16
            | Code::Add_r8_rm8
            | Code::Sub_r64_rm64
            | Code::Sub_r32_rm32
            | Code::Sub_r16_rm16
            | Code::Sub_r8_rm8
            | Code::Cmp_r64_rm64
            | Code::Cmp_r32_rm32
            | Code::Cmp_r16_rm16
            | Code::Cmp_r8_rm8 => {
                let dreg = instruction.op0_register();
                let dbits = VMBits::from(dreg);
                let dst = VMReg::from(dreg);
                let sub = matches!(instruction.mnemonic(), Mnemonic::Sub | Mnemonic::Cmp);
                let store = matches!(instruction.mnemonic(), Mnemonic::Add | Mnemonic::Sub);

                match instruction.op1_kind() {
                    OpKind::Register => {
                        let sreg = instruction.op1_register();
                        let sbits = VMBits::from(sreg);
                        let src = VMReg::from(instruction.op1_register());
                        VMCmd::AddSubRegReg {
                            vop: VMOp::AddSubRegReg,
                            dbits,
                            dst,
                            sbits,
                            src,
                            sub,
                            store,
                        }
                    }
                    OpKind::Memory => {
                        let src = VMMem::from(instruction);
                        VMCmd::AddSubRegMem {
                            vop: VMOp::AddSubRegMem,
                            src,
                            sub,
                            store,
                            dbits,
                            dst,
                        }
                    }
                    _ => return None,
                }
            }
            Code::Add_rm64_r64
            | Code::Add_rm32_r32
            | Code::Add_rm16_r16
            | Code::Add_rm8_r8
            | Code::Sub_rm64_r64
            | Code::Sub_rm32_r32
            | Code::Sub_rm16_r16
            | Code::Sub_rm8_r8
            | Code::Cmp_rm64_r64
            | Code::Cmp_rm32_r32
            | Code::Cmp_rm16_r16
            | Code::Cmp_rm8_r8 => {
                let sreg = instruction.op1_register();
                let sbits = VMBits::from(sreg);
                let src = VMReg::from(sreg);
                let sub = matches!(instruction.mnemonic(), Mnemonic::Sub | Mnemonic::Cmp);
                let store = matches!(instruction.mnemonic(), Mnemonic::Add | Mnemonic::Sub);

                match instruction.op0_kind() {
                    OpKind::Register => {
                        let dreg = instruction.op0_register();
                        let dbits = VMBits::from(dreg);
                        let dst = VMReg::from(dreg);
                        VMCmd::AddSubRegReg {
                            vop: VMOp::AddSubRegReg,
                            dbits,
                            dst,
                            sbits,
                            src,
                            sub,
                            store,
                        }
                    }
                    OpKind::Memory => {
                        let dst = VMMem::from(instruction);
                        VMCmd::AddSubMemReg {
                            vop: VMOp::AddSubMemReg,
                            dst,
                            sub,
                            store,
                            sbits,
                            src,
                        }
                    }
                    _ => return None,
                }
            }
            Code::Lea_r16_m | Code::Lea_r32_m | Code::Lea_r64_m => {
                let reg = instruction.op0_register();
                let bits = VMBits::from(reg);
                let dst = VMReg::from(reg);
                let src = VMMem::from(instruction);

                VMCmd::SetRegMem {
                    vop: VMOp::SetRegMem,
                    dbits: bits,
                    load: false,
                    dst,
                    src,
                }
            }
            Code::Call_rel32_64 => {
                let dst = instruction.memory_displacement64().try_into().unwrap();
                VMCmd::BranchImm {
                    vop: VMOp::BranchImm,
                    ret: true,
                    dst,
                }
            }
            Code::Call_rm64 => match instruction.op0_kind() {
                OpKind::Register => VMCmd::BranchReg {
                    vop: VMOp::BranchReg,
                    ret: true,
                    dst: VMReg::from(instruction.op0_register()),
                },
                OpKind::Memory => VMCmd::BranchMem {
                    vop: VMOp::BranchMem,
                    ret: true,
                    dst: VMMem::from(instruction),
                },
                _ => return None,
            },
            Code::Jmp_rel8_64 | Code::Jmp_rel32_64 => {
                let dst = instruction.memory_displacement64().try_into().unwrap();
                VMCmd::BranchImm {
                    vop: VMOp::BranchImm,
                    ret: false,
                    dst,
                }
            }
            Code::Jmp_rm64 => match instruction.op0_kind() {
                OpKind::Register => VMCmd::BranchReg {
                    vop: VMOp::BranchReg,
                    dst: VMReg::from(instruction.op0_register()),
                    ret: false,
                },
                OpKind::Memory => VMCmd::BranchMem {
                    vop: VMOp::BranchMem,
                    dst: VMMem::from(instruction),
                    ret: false,
                },
                _ => return None,
            },
            Code::Ja_rel32_64 | Code::Ja_rel8_64 => {
                let dst = instruction.memory_displacement64().try_into().unwrap();
                // JA = CF=0 AND ZF=0
                VMCmd::Jcc {
                    vop: VMOp::Jcc,
                    logic: VMLogic::AND,
                    conds: vec![
                        VMCond {
                            cmp: VMTest::CMP,
                            lhs: VMFlag::Carry as u8,
                            rhs: 0,
                        },
                        VMCond {
                            cmp: VMTest::CMP,
                            lhs: VMFlag::Zero as u8,
                            rhs: 0,
                        },
                    ],
                    dst,
                }
            }
            Code::Jae_rel32_64 | Code::Jae_rel8_64 => {
                let dst = instruction.memory_displacement64().try_into().unwrap();
                // JAE = CF=0
                VMCmd::Jcc {
                    vop: VMOp::Jcc,
                    logic: VMLogic::AND,
                    conds: vec![VMCond {
                        cmp: VMTest::CMP,
                        lhs: VMFlag::Carry as u8,
                        rhs: 0,
                    }],
                    dst,
                }
            }
            Code::Jb_rel32_64 | Code::Jb_rel8_64 => {
                let dst = instruction.memory_displacement64().try_into().unwrap();
                // JB = CF=1
                VMCmd::Jcc {
                    vop: VMOp::Jcc,
                    logic: VMLogic::AND,
                    conds: vec![VMCond {
                        cmp: VMTest::CMP,
                        lhs: VMFlag::Carry as u8,
                        rhs: 1,
                    }],
                    dst,
                }
            }
            Code::Jbe_rel32_64 | Code::Jbe_rel8_64 => {
                let dst = instruction.memory_displacement64().try_into().unwrap();
                // JBE = CF=1 OR ZF=1
                VMCmd::Jcc {
                    vop: VMOp::Jcc,
                    logic: VMLogic::OR,
                    conds: vec![
                        VMCond {
                            cmp: VMTest::CMP,
                            lhs: VMFlag::Carry as u8,
                            rhs: 1,
                        },
                        VMCond {
                            cmp: VMTest::CMP,
                            lhs: VMFlag::Zero as u8,
                            rhs: 1,
                        },
                    ],
                    dst,
                }
            }
            Code::Je_rel32_64 | Code::Je_rel8_64 => {
                let dst = instruction.memory_displacement64().try_into().unwrap();
                // JE = ZF=1
                VMCmd::Jcc {
                    vop: VMOp::Jcc,
                    logic: VMLogic::AND,
                    conds: vec![VMCond {
                        cmp: VMTest::CMP,
                        lhs: VMFlag::Zero as u8,
                        rhs: 1,
                    }],
                    dst,
                }
            }
            Code::Jg_rel32_64 | Code::Jg_rel8_64 => {
                let dst = instruction.memory_displacement64().try_into().unwrap();
                // JG = ZF=0 AND SF=OF
                VMCmd::Jcc {
                    vop: VMOp::Jcc,
                    logic: VMLogic::AND,
                    conds: vec![
                        VMCond {
                            cmp: VMTest::CMP,
                            lhs: VMFlag::Zero as u8,
                            rhs: 0,
                        },
                        VMCond {
                            cmp: VMTest::EQ,
                            lhs: VMFlag::Sign as u8,
                            rhs: VMFlag::Overflow as u8,
                        },
                    ],
                    dst,
                }
            }
            Code::Jge_rel32_64 | Code::Jge_rel8_64 => {
                let dst = instruction.memory_displacement64().try_into().unwrap();
                // JGE = SF=OF
                VMCmd::Jcc {
                    vop: VMOp::Jcc,
                    logic: VMLogic::AND,
                    conds: vec![VMCond {
                        cmp: VMTest::EQ,
                        lhs: VMFlag::Sign as u8,
                        rhs: VMFlag::Overflow as u8,
                    }],
                    dst,
                }
            }
            Code::Jl_rel32_64 | Code::Jl_rel8_64 => {
                let dst = instruction.memory_displacement64().try_into().unwrap();
                // JL = SF<>OF
                VMCmd::Jcc {
                    vop: VMOp::Jcc,
                    logic: VMLogic::AND,
                    conds: vec![VMCond {
                        cmp: VMTest::NEQ,
                        lhs: VMFlag::Sign as u8,
                        rhs: VMFlag::Overflow as u8,
                    }],
                    dst,
                }
            }
            Code::Jle_rel32_64 | Code::Jle_rel8_64 => {
                let dst = instruction.memory_displacement64().try_into().unwrap();
                // JLE = ZF=1 OR SF<>OF
                VMCmd::Jcc {
                    vop: VMOp::Jcc,
                    logic: VMLogic::OR,
                    conds: vec![
                        VMCond {
                            cmp: VMTest::CMP,
                            lhs: VMFlag::Zero as u8,
                            rhs: 1,
                        },
                        VMCond {
                            cmp: VMTest::NEQ,
                            lhs: VMFlag::Sign as u8,
                            rhs: VMFlag::Overflow as u8,
                        },
                    ],
                    dst,
                }
            }
            Code::Jne_rel32_64 | Code::Jne_rel8_64 => {
                let dst = instruction.memory_displacement64().try_into().unwrap();
                // JNE = ZF=0
                VMCmd::Jcc {
                    vop: VMOp::Jcc,
                    logic: VMLogic::AND,
                    conds: vec![VMCond {
                        cmp: VMTest::CMP,
                        lhs: VMFlag::Zero as u8,
                        rhs: 0,
                    }],
                    dst,
                }
            }
            Code::Jno_rel32_64 | Code::Jno_rel8_64 => {
                let dst = instruction.memory_displacement64().try_into().unwrap();
                // JNO = OF=0
                VMCmd::Jcc {
                    vop: VMOp::Jcc,
                    logic: VMLogic::AND,
                    conds: vec![VMCond {
                        cmp: VMTest::CMP,
                        lhs: VMFlag::Overflow as u8,
                        rhs: 0,
                    }],
                    dst,
                }
            }
            Code::Jnp_rel32_64 | Code::Jnp_rel8_64 => {
                let dst = instruction.memory_displacement64().try_into().unwrap();
                // JNP = PF=0
                VMCmd::Jcc {
                    vop: VMOp::Jcc,
                    logic: VMLogic::AND,
                    conds: vec![VMCond {
                        cmp: VMTest::CMP,
                        lhs: VMFlag::Parity as u8,
                        rhs: 0,
                    }],
                    dst,
                }
            }
            Code::Jns_rel32_64 | Code::Jns_rel8_64 => {
                let dst = instruction.memory_displacement64().try_into().unwrap();
                // JNS = SF=0
                VMCmd::Jcc {
                    vop: VMOp::Jcc,
                    logic: VMLogic::AND,
                    conds: vec![VMCond {
                        cmp: VMTest::CMP,
                        lhs: VMFlag::Sign as u8,
                        rhs: 0,
                    }],
                    dst,
                }
            }
            Code::Jo_rel32_64 | Code::Jo_rel8_64 => {
                let dst = instruction.memory_displacement64().try_into().unwrap();
                // JO = OF=1
                VMCmd::Jcc {
                    vop: VMOp::Jcc,
                    logic: VMLogic::AND,
                    conds: vec![VMCond {
                        cmp: VMTest::CMP,
                        lhs: VMFlag::Overflow as u8,
                        rhs: 1,
                    }],
                    dst,
                }
            }
            Code::Jp_rel32_64 | Code::Jp_rel8_64 => {
                let dst = instruction.memory_displacement64().try_into().unwrap();
                // JP = PF=1
                VMCmd::Jcc {
                    vop: VMOp::Jcc,
                    logic: VMLogic::AND,
                    conds: vec![VMCond {
                        cmp: VMTest::CMP,
                        lhs: VMFlag::Parity as u8,
                        rhs: 1,
                    }],
                    dst,
                }
            }
            Code::Js_rel32_64 | Code::Js_rel8_64 => {
                let dst = instruction.memory_displacement64().try_into().unwrap();
                // JS = SF=1
                VMCmd::Jcc {
                    vop: VMOp::Jcc,
                    logic: VMLogic::AND,
                    conds: vec![VMCond {
                        cmp: VMTest::CMP,
                        lhs: VMFlag::Sign as u8,
                        rhs: 1,
                    }],
                    dst,
                }
            }
            Code::Nopw
            | Code::Nopd
            | Code::Nopq
            | Code::Nop_rm16
            | Code::Nop_rm32
            | Code::Nop_rm64 => VMCmd::Nop { vop: VMOp::Nop },
            _ => {
                // println!("{instruction} -> {:?}", instruction.code());
                return None;
            }
        };

        vinstructions.extend_from_slice(&bytecode.encode(mapper));

        i += 1;
    }

    Some(vinstructions)
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\cleanup.rs =====

use iced_x86::code_asm::{ptr, r12, r13, r8, r8d, rax, rcx, rdx, rsp};

use crate::{
    runtime::{DataDef, Runtime, StringDef},
    VM_STACK_SIZE,
};

pub fn build(rt: &mut Runtime) {
    // push r12
    rt.asm.push(r12).unwrap();
    // push r13
    rt.asm.push(r13).unwrap();

    // sub rsp, 0x28
    rt.asm.sub(rsp, 0x28).unwrap();

    // lea rcx, [...]; lea rdx, [...]; call ...
    rt.get_proc_address(StringDef::KERNEL32, StringDef::GetProcessHeap);
    // call rax
    rt.asm.call(rax).unwrap();
    // mov r12, rax
    rt.asm.mov(r12, rax).unwrap();

    // lea rcx, [...]; lea rdx, [...]; call ...
    rt.get_proc_address(StringDef::Ntdll, StringDef::RtlFreeHeap);
    // mov r13, rax
    rt.asm.mov(r13, rax).unwrap();

    // mov rcx, r12
    rt.asm.mov(rcx, r12).unwrap();
    // xor rdx, rdx
    rt.asm.xor(rdx, rdx).unwrap();
    // mov r8d, [...]
    rt.asm
        .mov(r8d, ptr(rt.data_labels[&DataDef::VmStateTlsIndex]))
        .unwrap();
    // mov r8, gs:[0x1480 + r8*8]
    rt.asm.mov(r8, ptr(0x1480 + r8 * 8).gs()).unwrap();
    // call r14
    rt.asm.call(r13).unwrap();

    // mov rcx, r12
    rt.asm.mov(rcx, r12).unwrap();
    // xor rdx, rdx
    rt.asm.xor(rdx, rdx).unwrap();
    // mov r8d, [...]
    rt.asm
        .mov(r8d, ptr(rt.data_labels[&DataDef::VmStackTlsIndex]))
        .unwrap();
    // mov r8, gs:[0x1480 + r8*8]
    rt.asm.mov(r8, ptr(0x1480 + r8 * 8).gs()).unwrap();
    // sub r8, ...
    rt.asm.sub(r8, VM_STACK_SIZE as i32).unwrap();
    // call r14
    rt.asm.call(r13).unwrap();

    // add rsp, 0x28
    rt.asm.add(rsp, 0x28).unwrap();

    // pop r13
    rt.asm.pop(r13).unwrap();
    // pop r12
    rt.asm.pop(r12).unwrap();
    // ret
    rt.asm.ret().unwrap();
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\crypt.rs =====

use iced_x86::code_asm::{
    al, byte_ptr, eax, ptr, r12, r13, r13b, r14, r14b, r14d, r15, r8, r9b, rax, rcx, rdx,
};

use crate::{
    runtime::{DataDef, Runtime},
    vm::stack,
};

// void (unsigned char*, unsigned short, unsigned char*, bool)
pub fn build(rt: &mut Runtime) {
    let mut derive_key = rt.asm.create_label();
    let mut wait_for_previous = rt.asm.create_label();
    let mut wait_for_current = rt.asm.create_label();
    let mut crypt_loop = rt.asm.create_label();
    let mut is_decrypt = rt.asm.create_label();
    let mut continue_loop = rt.asm.create_label();
    let mut unlock = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);
    // push r14
    stack::push(rt, r14);
    // push r15
    stack::push(rt, r15);

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();
    // mov r13b, r9b
    rt.asm.mov(r13b, r9b).unwrap();
    // add rcx, 0x2
    rt.asm.add(rcx, 0x2).unwrap();
    // add rdx, rcx
    rt.asm.add(rdx, rcx).unwrap();

    // lea rax, [...]
    rt.asm
        .lea(rax, ptr(rt.data_labels[&DataDef::VmCode]))
        .unwrap();
    // mov r15, r12
    rt.asm.mov(r15, r12).unwrap();
    // sub r15, rax
    rt.asm.sub(r15, rax).unwrap();

    // test r13b, r13b
    rt.asm.test(r13b, r13b).unwrap();
    // jz ...
    rt.asm.jz(derive_key).unwrap();

    // test r15, r15
    rt.asm.test(r15, r15).unwrap();
    // jz ...
    rt.asm.jz(derive_key).unwrap();

    rt.asm.set_label(&mut wait_for_previous).unwrap();
    {
        // xor eax, eax
        rt.asm.xor(eax, eax).unwrap();
        // mov r9b, 0x1
        rt.asm.mov(r9b, 0x1).unwrap();
        // lock cmpxchg [r12 - 0x1], r9b
        rt.asm.lock().cmpxchg(byte_ptr(r12 - 0x1), r9b).unwrap();
        // jnz ...
        rt.asm.jnz(wait_for_previous).unwrap();
    }

    rt.asm.set_label(&mut wait_for_current).unwrap();
    {
        // xor eax, eax
        rt.asm.xor(eax, eax).unwrap();
        // mov r9b, 0x1
        rt.asm.mov(r9b, 0x1).unwrap();
        // lock cmpxchg [rdx], r9b
        rt.asm.lock().cmpxchg(byte_ptr(rdx), r9b).unwrap();
        // jnz ...
        rt.asm.jnz(wait_for_current).unwrap();
    }

    rt.asm.set_label(&mut derive_key).unwrap();
    {
        let mut load_key = rt.asm.create_label();

        // test r15, r15
        rt.asm.test(r15, r15).unwrap();
        // jnz ...
        rt.asm.jnz(load_key).unwrap();

        // mov r14, [...]
        rt.asm
            .mov(r14, ptr(rt.data_labels[&DataDef::VmKeySeed]))
            .unwrap();
        // jmp ...
        rt.asm.jmp(crypt_loop).unwrap();

        rt.asm.set_label(&mut load_key).unwrap();
        {
            // mov r14, [r12 - 0x4]
            rt.asm.mov(r14d, ptr(r12 - 0x4)).unwrap();
        }
    }

    rt.asm.set_label(&mut crypt_loop).unwrap();
    {
        // cmp rcx, rdx
        rt.asm.cmp(rcx, rdx).unwrap();
        // je ...
        rt.asm.je(unlock).unwrap();
        // mov al, [rcx]
        rt.asm.mov(al, byte_ptr(rcx)).unwrap();
        // xor [rcx], r14b
        rt.asm.xor(byte_ptr(rcx), r14b).unwrap();
        // test r13b, r13b
        rt.asm.test(r13b, r13b).unwrap();
        // jnz ...
        rt.asm.jnz(is_decrypt).unwrap();
        // movzx rax, [rcx]
        rt.asm.movzx(rax, byte_ptr(rcx)).unwrap();
        // jmp ...
        rt.asm.jmp(continue_loop).unwrap();

        rt.asm.set_label(&mut is_decrypt).unwrap();
        {
            // movzx rax, al
            rt.asm.movzx(rax, al).unwrap();
        }

        rt.asm.set_label(&mut continue_loop).unwrap();
        {
            // xor rax, [r8]
            rt.asm.xor(rax, byte_ptr(r8)).unwrap();
            // xor r14, rax
            rt.asm.xor(r14, rax).unwrap();
            // mov rax, [...]
            rt.asm
                .mov(rax, ptr(rt.data_labels[&DataDef::VmKeyMul]))
                .unwrap();
            // imul r14, rax
            rt.asm.imul_2(r14, rax).unwrap();
            // mov rax, [...]
            rt.asm
                .mov(rax, ptr(rt.data_labels[&DataDef::VmKeyAdd]))
                .unwrap();
            // add r14, rax
            rt.asm.add(r14, rax).unwrap();
            // inc rcx
            rt.asm.inc(rcx).unwrap();
            // jmp ...
            rt.asm.jmp(crypt_loop).unwrap();
        }
    }

    rt.asm.set_label(&mut unlock).unwrap();
    {
        // test r13b, r13b
        rt.asm.test(r13b, r13b).unwrap();
        // jnz ...
        rt.asm.jnz(epilogue).unwrap();

        // test r15, r15
        rt.asm.test(r15, r15).unwrap();
        // jz ...
        rt.asm.jz(epilogue).unwrap();

        // mov [r12 - 0x1], 0x0
        rt.asm.mov(byte_ptr(r12 - 0x1), 0x0).unwrap();
        // mov [rdx], 0x0
        rt.asm.mov(byte_ptr(rdx), 0x0).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // pop r15
        stack::pop(rt, r15);
        // pop r14
        stack::pop(rt, r14);
        // pop r13
        stack::pop(rt, r13);
        // pop r12
        stack::pop(rt, r12);
        // ret
        stack::ret(rt);
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\dispatch.rs =====

use iced_x86::code_asm::{byte_ptr, ptr, r12, r13, r14, r15, r8, r9b, rax, rcx, rdx, word_ptr};

use crate::{
    runtime::{DataDef, FnDef, Runtime},
    vm::{bytecode::VMReg, stack, utils},
};

// void (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut execute_loop = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);
    // push r14
    stack::push(rt, r14);
    // push r15
    stack::push(rt, r15);

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();
    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // mov r14, [r12 + ...]
    utils::mov_reg_vreg_64(rt, r12, VMReg::Vra, r14);

    // mov [r12 + ...], r13
    utils::mov_vreg_reg_64(rt, r12, r13, VMReg::Vbp);
    // movzx rax, [r13]
    rt.asm.movzx(rax, word_ptr(r13)).unwrap();
    // add r13, 0x2
    rt.asm.add(r13, 0x2).unwrap();
    // mov [r12 + ...], rax
    utils::mov_vreg_reg_64(rt, r12, rax, VMReg::Vbl);

    // lea r15, [r13 + rax]
    rt.asm.lea(r15, ptr(r13 + rax)).unwrap();

    // mov rcx, [r14 + ...]
    utils::mov_reg_vreg_64(rt, r12, VMReg::Vbp, rcx);
    // mov rdx, [r14 + ...]
    utils::mov_reg_vreg_64(rt, r12, VMReg::Vbl, rdx);
    // mov r8, [r14 + ...]
    utils::mov_reg_vreg_64(rt, r12, VMReg::Vsk, r8);
    // mov r9b, 0x1
    rt.asm.mov(r9b, 0x1).unwrap();
    // call ...
    stack::call_with_label(rt, rt.func_labels[&FnDef::VmCrypt], &execute_loop);

    rt.asm.set_label(&mut execute_loop).unwrap();
    {
        // cmp r13, r15
        rt.asm.cmp(r13, r15).unwrap();
        // je ...
        rt.asm.je(epilogue).unwrap();

        // movzx r8, [r13] -> op
        rt.asm.movzx(r8, byte_ptr(r13)).unwrap();
        // add r13, 0x1
        rt.asm.add(r13, 0x1).unwrap();

        // lea rax, [...]
        rt.asm
            .lea(rax, ptr(rt.data_labels[&DataDef::VmHandlers]))
            .unwrap();
        // mov rax, [rax + r8*8]
        rt.asm.mov(rax, ptr(rax + r8 * 8)).unwrap();

        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // mov rdx, r13
        rt.asm.mov(rdx, r13).unwrap();
        // call rax
        stack::call(rt, rax);

        // mov r13, rax
        rt.asm.mov(r13, rax).unwrap();

        // cmp [r12 + ...], r14
        utils::cmp_vreg_reg_64(rt, r12, VMReg::Vra, r14);
        // jne ...
        rt.asm.jne(epilogue).unwrap();

        // jmp ...
        rt.asm.jmp(execute_loop).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rcx, [r14 + ...]
        utils::mov_reg_vreg_64(rt, r12, VMReg::Vbp, rcx);
        // mov rdx, [r14 + ...]
        utils::mov_reg_vreg_64(rt, r12, VMReg::Vbl, rdx);
        // mov r8, [r14 + ...]
        utils::mov_reg_vreg_64(rt, r12, VMReg::Vsk, r8);
        // xor r9b, r9b
        rt.asm.xor(r9b, r9b).unwrap();
        // call ...
        stack::call(rt, rt.func_labels[&FnDef::VmCrypt]);

        // pop r15
        stack::pop(rt, r15);
        // pop r14
        stack::pop(rt, r14);
        // pop r13
        stack::pop(rt, r13);
        // pop r12
        stack::pop(rt, r12);
        // ret
        stack::ret(rt);
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\entry.rs =====

use iced_x86::code_asm::{byte_ptr, ecx, ptr, r12, r12b, r12d, rax, rcx, rdi, rdx, rsi, rsp};
use rand::seq::SliceRandom;

use crate::{
    mapper::Mappable as _,
    runtime::{BoolDef, DataDef, FnDef, Runtime, StringDef},
    vm::{
        bytecode::{VMOp, VMReg},
        stack, utils, VREG_TO_REG,
    },
};

// void (unsigned int)
pub fn build(rt: &mut Runtime) {
    let mut wait_for_global_lock = rt.asm.create_label();
    let mut save_global_state = rt.asm.create_label();
    let mut invoke_ginit = rt.asm.create_label();
    let mut invoke_tinit = rt.asm.create_label();
    let mut initialize_state = rt.asm.create_label();
    let mut initialize_execution = rt.asm.create_label();

    // pushfq
    rt.asm.pushfq().unwrap();
    // push r12
    rt.asm.push(r12).unwrap();

    // mov r12d, [...]
    rt.asm
        .mov(r12d, ptr(rt.data_labels[&DataDef::VmStateTlsIndex]))
        .unwrap();
    // test r12d, r12d
    rt.asm.test(r12d, r12d).unwrap();
    // jz ...
    rt.asm.jz(wait_for_global_lock).unwrap();

    // mov r12, [0x1480 + r12*8]
    rt.asm.mov(r12, ptr(0x1480 + r12 * 8).gs()).unwrap();
    // test r12, r12
    rt.asm.test(r12, r12).unwrap();
    // jz ...
    rt.asm.jz(wait_for_global_lock).unwrap();

    // jmp ...
    rt.asm.jmp(initialize_state).unwrap();

    rt.asm.set_label(&mut wait_for_global_lock).unwrap();
    {
        // mov r12b, 0x1
        rt.asm.mov(r12b, 0x1).unwrap();
        // lock xchg [...], r12b
        rt.asm
            .lock()
            .xchg(ptr(rt.bool_labels[&BoolDef::VmIsLocked]), r12b)
            .unwrap();
        // test r12b, r12b
        rt.asm.test(r12b, r12b).unwrap();
        // jnz ...
        rt.asm.jnz(wait_for_global_lock).unwrap();
    }

    rt.asm.set_label(&mut save_global_state).unwrap();
    {
        // lea r12, [...]
        rt.asm
            .lea(r12, ptr(rt.data_labels[&DataDef::VmGlobalState]))
            .unwrap();

        for (vreg, reg) in VREG_TO_REG {
            // mov [r12 + ...], ...
            utils::mov_vreg_reg_64(rt, r12, *reg, *vreg);
        }
    }

    // mov r12d, [...]
    rt.asm
        .mov(r12d, ptr(rt.data_labels[&DataDef::VmStateTlsIndex]))
        .unwrap();
    // test r12d, r12d
    rt.asm.test(r12d, r12d).unwrap();
    // jz ...
    rt.asm.jz(invoke_ginit).unwrap();
    // jmp ...
    rt.asm.jmp(invoke_tinit).unwrap();

    rt.asm.set_label(&mut invoke_ginit).unwrap();
    {
        rt.asm.call(rt.func_labels[&FnDef::VmGInit]).unwrap();
    }

    rt.asm.set_label(&mut invoke_tinit).unwrap();
    {
        rt.asm.call(rt.func_labels[&FnDef::VmTInit]).unwrap();
    }

    // mov r12d, [...]
    rt.asm
        .mov(r12d, ptr(rt.data_labels[&DataDef::VmStateTlsIndex]))
        .unwrap();
    // mov r12, [0x1480 + r12*8]
    rt.asm.mov(r12, ptr(0x1480 + r12 * 8).gs()).unwrap();

    // lea rsi, [...]
    rt.asm
        .lea(rsi, ptr(rt.data_labels[&DataDef::VmGlobalState]))
        .unwrap();
    // mov rdi, r12
    rt.asm.mov(rdi, r12).unwrap();
    // mov rcx, ...
    rt.asm.mov(rcx, VMReg::COUNT as u64).unwrap();
    // rep movsq
    rt.asm.rep().movsq().unwrap();

    // call ...
    rt.asm
        .call(rt.func_labels[&FnDef::VmVehInitialize])
        .unwrap();

    // mov rax, gs:[0x60] -> PEB *TEB->ProcessEnvironmentBlock
    rt.asm.mov(rax, ptr(0x60).gs()).unwrap();
    // mov rax, [rax + 0x10] -> PVOID PEB->ImageBaseAddress
    rt.asm.mov(rax, ptr(rax + 0x10)).unwrap();
    // mov [r12 + ...], rax
    utils::mov_vreg_reg_64(rt, r12, rax, VMReg::VB);

    // lea rcx, [...]; lea rdx, [...]; call ...
    rt.get_proc_address(StringDef::Ntdll, StringDef::NtQueryInformationProcess);
    // mov [...], rax
    utils::mov_vreg_reg_64(rt, r12, rax, VMReg::Vsk);

    let mut table = [
        (VMOp::PushPopRegs, FnDef::VmHandlerPushPopRegs),
        (VMOp::PushImm, FnDef::VmHandlerPushImm),
        (VMOp::PushReg, FnDef::VmHandlerPushReg),
        (VMOp::PopReg, FnDef::VmHandlerPopReg),
        (VMOp::SetRegImm, FnDef::VmHandlerSetRegImm),
        (VMOp::SetRegReg, FnDef::VmHandlerSetRegReg),
        (VMOp::SetRegMem, FnDef::VmHandlerSetRegMem),
        (VMOp::SetMemImm, FnDef::VmHandlerSetMemImm),
        (VMOp::SetMemReg, FnDef::VmHandlerSetMemReg),
        (VMOp::AddSubRegImm, FnDef::VmHandlerAddSubRegImm),
        (VMOp::AddSubRegReg, FnDef::VmHandlerAddSubRegReg),
        (VMOp::AddSubRegMem, FnDef::VmHandlerAddSubRegMem),
        (VMOp::AddSubMemImm, FnDef::VmHandlerAddSubMemImm),
        (VMOp::AddSubMemReg, FnDef::VmHandlerAddSubMemReg),
        (VMOp::BranchImm, FnDef::VmHandlerBranchImm),
        (VMOp::BranchReg, FnDef::VmHandlerBranchReg),
        (VMOp::BranchMem, FnDef::VmHandlerBranchMem),
        (VMOp::Jcc, FnDef::VmHandlerJcc),
        (VMOp::Nop, FnDef::VmHandlerNop),
    ];

    let mut rng = rand::thread_rng();
    table.shuffle(&mut rng);

    // lea rax, [...]
    rt.asm
        .lea(rax, ptr(rt.data_labels[&DataDef::VmHandlers]))
        .unwrap();

    rt.with_chain(|rt| {
        // xor rcx, rcx
        rt.asm.xor(rcx, rcx).unwrap();

        for (op, def) in table {
            let key = rt.mark_as_encrypted(rt.func_labels[&def]);
            // mov rdx, ...
            rt.asm.mov(rdx, 0x0u64).unwrap();
            // xor rcx, rdx
            rt.asm.xor(rcx, rdx).unwrap();
            // mov rdx, ...
            rt.asm.mov(rdx, key).unwrap();
            // xor rcx, rdx
            rt.asm.xor(rcx, rdx).unwrap();

            // mov rdx, rcx
            rt.asm.mov(rdx, rcx).unwrap();

            // add rdx, [...]
            utils::add_reg_vreg_64(rt, r12, VMReg::VB, rdx);
            // mov [rax + ...], rdx
            rt.asm.mov(ptr(rax + rt.mapper.index(op) * 8), rdx).unwrap();
        }
    });

    // mov [...], 0x0
    rt.asm
        .mov(byte_ptr(rt.bool_labels[&BoolDef::VmIsLocked]), 0x0)
        .unwrap();

    // jmp ...
    rt.asm.jmp(initialize_execution).unwrap();

    rt.asm.set_label(&mut initialize_state).unwrap();
    {
        // mov r12d, [...]
        rt.asm
            .mov(r12d, ptr(rt.data_labels[&DataDef::VmStateTlsIndex]))
            .unwrap();
        // mov r12, [0x1480 + r12*8]
        rt.asm.mov(r12, ptr(0x1480 + r12 * 8).gs()).unwrap();

        for (vreg, reg) in VREG_TO_REG {
            // mov [r12 + ...], ...
            utils::mov_vreg_reg_64(rt, r12, *reg, *vreg);
        }
    }

    rt.asm.set_label(&mut initialize_execution).unwrap();
    {
        // pop rcx -> r12
        rt.asm.pop(rcx).unwrap();
        // mov [r12 + ...], ...
        utils::mov_vreg_reg_64(rt, r12, rcx, VMReg::R12);

        // pop rcx -> flags
        rt.asm.pop(rcx).unwrap();
        // mov [r12 + ...], rcx
        utils::mov_vreg_reg_64(rt, r12, rcx, VMReg::Flags);

        // pop rcx -> ret
        rt.asm.pop(rdx).unwrap();
        // mov [r12 + ...], rcx
        utils::mov_vreg_reg_64(rt, r12, rdx, VMReg::Vra);
        // mov [r12 + ...], rcx
        utils::mov_vreg_reg_64(rt, r12, rdx, VMReg::Vea);

        // sub rdx, [...]
        utils::sub_reg_vreg_64(rt, r12, VMReg::VB, rdx);

        // pop rcx -> index
        rt.asm.pop(rcx).unwrap();
        // xor rcx, rdx
        rt.asm.xor(rcx, rdx).unwrap();
        // and ecx, 0x0FFFFFFF
        rt.asm.and(ecx, 0x0FFFFFFF).unwrap();
        // lea rdx, [...]
        rt.asm
            .lea(rdx, ptr(rt.data_labels[&DataDef::VmTable]))
            .unwrap();

        // lea rdx, [rdx + rcx*8]
        rt.asm.lea(rdx, ptr(rdx + rcx * 8)).unwrap();

        // mov ecx, [rdx] -> displ
        rt.asm.mov(ecx, ptr(rdx)).unwrap();
        // sub [r12 + ...], rcx
        utils::sub_vreg_reg_64(rt, r12, rcx, VMReg::Vea);
        // add [r12 + ...], rcx
        utils::add_vreg_reg_64(rt, r12, rcx, VMReg::Vra);

        // mov ecx, [rdx + 0x4] -> offset
        rt.asm.mov(ecx, ptr(rdx + 0x4)).unwrap();

        // lea rdx, [...]
        rt.asm
            .lea(rdx, ptr(rt.data_labels[&DataDef::VmCode]))
            .unwrap();
        // add rdx, rcx
        rt.asm.add(rdx, rcx).unwrap();

        // mov [r12 + ...], rsp
        utils::mov_vreg_reg_64(rt, r12, rsp, VMReg::Rsp);
    }

    // mov rcx, r12
    rt.asm.mov(rcx, r12).unwrap();
    // call ...
    stack::call(rt, rt.func_labels[&FnDef::VmDispatch]);

    // jmp ...
    rt.asm.jmp(rt.func_labels[&FnDef::VmExit]).unwrap();
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\exit.rs =====

use iced_x86::code_asm::{ptr, r12, r12d, rsp};

use crate::{
    runtime::{DataDef, Runtime},
    vm::{bytecode::VMReg, utils, VREG_TO_REG},
};

pub fn build(rt: &mut Runtime) {
    // mov r12d, [...]
    rt.asm
        .mov(r12d, ptr(rt.data_labels[&DataDef::VmStateTlsIndex]))
        .unwrap();
    // mov r12, gs:[0x1480 + r12*8]
    rt.asm.mov(r12, ptr(0x1480 + r12 * 8).gs()).unwrap();

    // mov rsp, [r12 + ...]
    utils::mov_reg_vreg_64(rt, r12, VMReg::Rsp, rsp);

    // mov rcx, [...]
    utils::push_vreg_64(rt, r12, VMReg::Flags);
    // popfq
    rt.asm.popfq().unwrap();

    for (vreg, reg) in VREG_TO_REG {
        // mov ...,  [r12 + ...]
        utils::mov_reg_vreg_64(rt, r12, *vreg, *reg);
    }

    // push [r12 + ...]
    utils::push_vreg_64(rt, r12, VMReg::Vra);

    // mov r12, [r12 + ...]
    utils::mov_reg_vreg_64(rt, r12, VMReg::R12, r12);

    // ret
    rt.asm.ret().unwrap();
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\ginit.rs =====

use iced_x86::code_asm::{eax, ptr, r12, rax, rcx, rdx, rsp};

use crate::runtime::{DataDef, FnDef, Runtime, StringDef};

pub fn build(rt: &mut Runtime) {
    // push r12
    rt.asm.push(r12).unwrap();

    // sub rsp, 0x28
    rt.asm.sub(rsp, 0x28).unwrap();

    // lea rcx, [...]; lea rdx, [...]; call ...
    rt.get_proc_address(StringDef::KERNEL32, StringDef::TlsAlloc);
    // mov r12, rax
    rt.asm.mov(r12, rax).unwrap();

    // call r12
    rt.asm.call(r12).unwrap();
    // mov [...], eax
    rt.asm
        .mov(ptr(rt.data_labels[&DataDef::VmStateTlsIndex]), eax)
        .unwrap();

    // call r12
    rt.asm.call(r12).unwrap();
    // mov [...], eax
    rt.asm
        .mov(ptr(rt.data_labels[&DataDef::VmStackTlsIndex]), eax)
        .unwrap();

    // lea rcx, [...]; lea rdx, [...]; call ...
    rt.get_proc_address(StringDef::Ntdll, StringDef::RtlFlsAlloc);
    // lea rcx, [...]
    rt.asm
        .lea(rcx, ptr(rt.func_labels[&FnDef::VmCleanup]))
        .unwrap();
    // lea rdx, [...]
    rt.asm
        .lea(rdx, ptr(rt.data_labels[&DataDef::VmCleanupFlsIndex]))
        .unwrap();
    // call rax
    rt.asm.call(rax).unwrap();

    // add rsp, 0x28
    rt.asm.add(rsp, 0x28).unwrap();

    // pop r12
    rt.asm.pop(r12).unwrap();
    // ret
    rt.asm.ret().unwrap();
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\arithmetic\addsub16.rs =====

use iced_x86::code_asm::{ax, ptr, r8w, r9b, rdx};

use crate::{
    runtime::{FnDef, Runtime},
    vm::stack,
};

// void (unsigned long*, unsigned long*, unsigned short, byte)
pub fn build(rt: &mut Runtime) {
    let mut sub = rt.asm.create_label();
    let mut done = rt.asm.create_label();

    // mov ax, [rdx]
    rt.asm.mov(ax, ptr(rdx)).unwrap();

    // test r9b, 0x1 -> sub
    rt.asm.test(r9b, 0x1).unwrap();
    // jnz ...
    rt.asm.jnz(sub).unwrap();

    // add ax, r8b
    rt.asm.add(ax, r8w).unwrap();
    // jmp ...
    rt.asm.jmp(done).unwrap();

    rt.asm.set_label(&mut sub).unwrap();
    {
        // sub ax, r8b
        rt.asm.sub(ax, r8w).unwrap();
    }

    rt.asm.set_label(&mut done).unwrap();
    {
        let mut flags = rt.asm.create_label();

        // pushfq
        stack::pushfq(rt);

        // test r9b, 0x2 -> store
        rt.asm.test(r9b, 0x2).unwrap();
        // jz ...
        rt.asm.jz(flags).unwrap();

        // mov [rdx], ax
        rt.asm.mov(ptr(rdx), ax).unwrap();

        rt.asm.set_label(&mut flags).unwrap();
        {
            // pop rdx
            stack::pop(rt, rdx);
            // call ...
            stack::call(rt, rt.func_labels[&FnDef::VmArithmeticFlags]);
            // ret
            stack::ret(rt);
        }
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\arithmetic\addsub32.rs =====

use iced_x86::code_asm::{eax, ptr, r8d, r9b, rax, rdx};

use crate::{
    runtime::{FnDef, Runtime},
    vm::stack,
};

// void (unsigned long*, unsigned long*, unsigned int, byte)
pub fn build(rt: &mut Runtime) {
    let mut sub = rt.asm.create_label();
    let mut done = rt.asm.create_label();

    // mov eax, [rdx]
    rt.asm.mov(eax, ptr(rdx)).unwrap();

    // test r9b, 0x1 -> sub
    rt.asm.test(r9b, 0x1).unwrap();
    // jnz ...
    rt.asm.jnz(sub).unwrap();

    // add eax, r8d
    rt.asm.add(eax, r8d).unwrap();
    // jmp ...
    rt.asm.jmp(done).unwrap();

    rt.asm.set_label(&mut sub).unwrap();
    {
        // sub eax, r8d
        rt.asm.sub(eax, r8d).unwrap();
    }

    rt.asm.set_label(&mut done).unwrap();
    {
        let mut extend = rt.asm.create_label();
        let mut flags = rt.asm.create_label();

        // pushfq
        stack::pushfq(rt);

        // test r9b, 0x2 -> store
        rt.asm.test(r9b, 0x2).unwrap();
        // jz ...
        rt.asm.jz(flags).unwrap();

        // test r9b, 0x4 -> memory
        rt.asm.test(r9b, 0x4).unwrap();
        // jz ...
        rt.asm.jz(extend).unwrap();

        // mov [rdx], eax
        rt.asm.mov(ptr(rdx), eax).unwrap();
        // jmp ...
        rt.asm.jmp(flags).unwrap();

        rt.asm.set_label(&mut extend).unwrap();
        {
            // mov [rdx], rax
            rt.asm.mov(ptr(rdx), rax).unwrap();
        }

        rt.asm.set_label(&mut flags).unwrap();
        {
            // pop rdx
            stack::pop(rt, rdx);
            // call ...
            stack::call(rt, rt.func_labels[&FnDef::VmArithmeticFlags]);
            // ret
            stack::ret(rt);
        }
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\arithmetic\addsub64.rs =====

use iced_x86::code_asm::{ptr, r8, r9b, rax, rdx};

use crate::{
    runtime::{FnDef, Runtime},
    vm::stack,
};

// void (unsigned long*, unsigned long*, unsigned long, byte)
pub fn build(rt: &mut Runtime) {
    let mut sub = rt.asm.create_label();
    let mut done = rt.asm.create_label();

    // mov rax, [rdx]
    rt.asm.mov(rax, ptr(rdx)).unwrap();

    // test r9b, 0x1 -> sub
    rt.asm.test(r9b, 0x1).unwrap();
    // jnz ...
    rt.asm.jnz(sub).unwrap();

    // add rax, r8
    rt.asm.add(rax, r8).unwrap();
    // jmp ...
    rt.asm.jmp(done).unwrap();

    rt.asm.set_label(&mut sub).unwrap();
    {
        // sub rax, r8
        rt.asm.sub(rax, r8).unwrap();
    }

    rt.asm.set_label(&mut done).unwrap();
    {
        let mut flags = rt.asm.create_label();

        // pushfq
        stack::pushfq(rt);

        // test r9b, 0x2 -> store
        rt.asm.test(r9b, 0x2).unwrap();
        // jz ...
        rt.asm.jz(flags).unwrap();

        // mov [rdx], rax
        rt.asm.mov(ptr(rdx), rax).unwrap();

        rt.asm.set_label(&mut flags).unwrap();
        {
            // pop rdx
            stack::pop(rt, rdx);
            // call ...
            stack::call(rt, rt.func_labels[&FnDef::VmArithmeticFlags]);
            // ret
            stack::ret(rt);
        }
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\arithmetic\addsub8.rs =====

use iced_x86::code_asm::{al, ptr, r8b, r9b, rdx};

use crate::{
    runtime::{FnDef, Runtime},

    vm::stack,
};

// void (unsigned long*, unsigned long*, byte, byte)
pub fn build(rt: &mut Runtime) {
    let mut sub = rt.asm.create_label();
    let mut done = rt.asm.create_label();

    // mov al, [rdx]
    rt.asm.mov(al, ptr(rdx)).unwrap();

    // test r9b, 0x1 -> sub
    rt.asm.test(r9b, 0x1).unwrap();
    // jnz ...
    rt.asm.jnz(sub).unwrap();

    // add al, r8b
    rt.asm.add(al, r8b).unwrap();
    // jmp ...
    rt.asm.jmp(done).unwrap();

    rt.asm.set_label(&mut sub).unwrap();
    {
        // sub al, r8b
        rt.asm.sub(al, r8b).unwrap();
    }

    rt.asm.set_label(&mut done).unwrap();
    {
        let mut flags = rt.asm.create_label();

        // pushfq
        stack::pushfq(rt);

        // test r9b, 0x2 -> store
        rt.asm.test(r9b, 0x2).unwrap();
        // jz ...
        rt.asm.jz(flags).unwrap();

        // mov [rdx], al
        rt.asm.mov(ptr(rdx), al).unwrap();

        rt.asm.set_label(&mut flags).unwrap();
        {
            // pop rdx
            stack::pop(rt, rdx);
            // call ...
            stack::call(rt, rt.func_labels[&FnDef::VmArithmeticFlags]);
            // ret
            stack::ret(rt);
        }
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\arithmetic\addsubmemimm.rs =====

use iced_x86::code_asm::{ptr, r12, r13, r14, r14b, r8, r8b, r8d, r8w, r9b, rax, rcx, rdx};

use crate::{
    runtime::{FnDef, Runtime},

    vm::stack,
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut byte = rt.asm.create_label();
    let mut word = rt.asm.create_label();
    let mut dword = rt.asm.create_label();
    let mut qword = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);
    // push r14
    stack::push(rt, r14);

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();
    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // call ...
    stack::call(rt, rt.func_labels[&FnDef::ComputeAddress]);

    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // xor r14b, r14b
    rt.asm.xor(r14b, r14b).unwrap();

    // mov r8b, [r13] -> sub
    rt.asm.mov(r8b, ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();
    // or r14b, r8b
    rt.asm.or(r14b, r8b).unwrap();

    // mov r8b, [r13] -> store
    rt.asm.mov(r8b, ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();
    // shl r8b, 0x1
    rt.asm.shl(r8b, 0x1).unwrap();
    // or r14b, r8b
    rt.asm.or(r14b, r8b).unwrap();

    // or r14b, 0x4 -> memory
    rt.asm.or(r14b, 0x4).unwrap();

    // mov r8b, [r13] -> size
    rt.asm.mov(r8b, ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();

    // cmp r8b, ...
    rt.asm.cmp(r8b, 0x8).unwrap();
    // je ...
    rt.asm.je(qword).unwrap();
    // cmp r8b, ...
    rt.asm.cmp(r8b, 0x4).unwrap();
    // je ...
    rt.asm.je(dword).unwrap();
    // cmp r8b, ...
    rt.asm.cmp(r8b, 0x2).unwrap();
    // je ...
    rt.asm.je(word).unwrap();

    rt.asm.set_label(&mut byte).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // mov rdx, rax
        rt.asm.mov(rdx, rax).unwrap();
        // mov r8b, [r13]
        rt.asm.mov(r8b, ptr(r13)).unwrap();
        // add r13, 0x1
        rt.asm.add(r13, 0x1).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub8],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut word).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // mov rdx, rax
        rt.asm.mov(rdx, rax).unwrap();
        // mov r8b, [r13]
        rt.asm.mov(r8w, ptr(r13)).unwrap();
        // add r13, 0x1
        rt.asm.add(r13, 0x2).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub16],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut dword).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // mov rdx, rax
        rt.asm.mov(rdx, rax).unwrap();
        // mov r8d, [r13]
        rt.asm.mov(r8d, ptr(r13)).unwrap();
        // add r13, 0x1
        rt.asm.add(r13, 0x4).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub32],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut qword).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // mov rdx, rax
        rt.asm.mov(rdx, rax).unwrap();
        // mov r8, [r13]
        rt.asm.mov(r8, ptr(r13)).unwrap();
        // add r13, 0x8
        rt.asm.add(r13, 0x8).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub64],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, r13
        rt.asm.mov(rax, r13).unwrap();

        // pop r14
        stack::pop(rt, r14);
        // pop r13
        stack::pop(rt, r13);
        // pop r12
        stack::pop(rt, r12);
        // ret
        stack::ret(rt);
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\arithmetic\addsubmemreg.rs =====

use iced_x86::code_asm::{
    byte_ptr, ptr, r12, r13, r14, r14b, r8, r8b, r8d, r8w, r9, r9b, rax, rcx, rdx,
};

use crate::{
    runtime::{FnDef, Runtime},

    vm::{bytecode::VMBits, stack},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut lower8 = rt.asm.create_label();
    let mut higher8 = rt.asm.create_label();
    let mut lower16 = rt.asm.create_label();
    let mut lower32 = rt.asm.create_label();
    let mut lower64 = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);
    // push r14
    stack::push(rt, r14);

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();
    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // call ...
    stack::call(rt, rt.func_labels[&FnDef::ComputeAddress]);

    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // xor r14b, r14b
    rt.asm.xor(r14b, r14b).unwrap();

    // mov r8b, [r13] -> sub
    rt.asm.mov(r8b, ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();
    // or r14b, r8b
    rt.asm.or(r14b, r8b).unwrap();

    // mov r8b, [r13] -> store
    rt.asm.mov(r8b, ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();
    // shl r8b, 0x1
    rt.asm.shl(r8b, 0x1).unwrap();
    // or r14b, r8b
    rt.asm.or(r14b, r8b).unwrap();

    // or r14b, 0x4 -> memory
    rt.asm.or(r14b, 0x4).unwrap();

    // mov r8b, [r13] -> sbits
    rt.asm.mov(r8b, ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();

    // movzx r9, [r13] -> src
    rt.asm.movzx(r9, byte_ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();

    // cmp r8b, ...
    rt.asm
        .cmp(r8b, rt.mapper.index(VMBits::Lower64) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower64).unwrap();
    // cmp r8b, ...
    rt.asm
        .cmp(r8b, rt.mapper.index(VMBits::Lower32) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower32).unwrap();
    // cmp r8b, ...
    rt.asm
        .cmp(r8b, rt.mapper.index(VMBits::Lower16) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower16).unwrap();
    // cmp r8b, ...
    rt.asm
        .cmp(r8b, rt.mapper.index(VMBits::Higher8) as i32)
        .unwrap();
    // je ...
    rt.asm.je(higher8).unwrap();

    rt.asm.set_label(&mut lower8).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // mov rdx, rax
        rt.asm.mov(rdx, rax).unwrap();
        // mov r8b, [r12 + r9*8]
        rt.asm.mov(r8b, ptr(r12 + r9 * 8)).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub8],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut higher8).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // mov rdx, rax
        rt.asm.mov(rdx, rax).unwrap();
        // mov r8b, [r12 + r9*8 + 0x1]
        rt.asm.mov(r8b, ptr(r12 + r9 * 8 + 0x1)).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub8],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut lower16).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // mov rdx, rax
        rt.asm.mov(rdx, rax).unwrap();
        // mov r8w, [r12 + r9*8]
        rt.asm.mov(r8w, ptr(r12 + r9 * 8)).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub16],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut lower32).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // mov rdx, rax
        rt.asm.mov(rdx, rax).unwrap();
        // mov r8d, [r12 + r9*8]
        rt.asm.mov(r8d, ptr(r12 + r9 * 8)).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub32],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut lower64).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // mov rdx, rax
        rt.asm.mov(rdx, rax).unwrap();
        // mov r8, [r12 + r9*8]
        rt.asm.mov(r8, ptr(r12 + r9 * 8)).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub64],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, r13
        rt.asm.mov(rax, r13).unwrap();

        // pop r14
        stack::pop(rt, r14);
        // pop r13
        stack::pop(rt, r13);
        // pop r12
        stack::pop(rt, r12);
        // ret
        stack::ret(rt);
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\arithmetic\addsubregimm.rs =====

use iced_x86::code_asm::{
    al, byte_ptr, ptr, r12, r13, r13b, r14, r14b, r8, r8b, r8d, r8w, r9b, rax, rcx, rdx,
};

use crate::{
    runtime::{FnDef, Runtime},

    vm::{bytecode::VMBits, stack},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut lower8 = rt.asm.create_label();
    let mut higher8 = rt.asm.create_label();
    let mut lower16 = rt.asm.create_label();
    let mut lower32 = rt.asm.create_label();
    let mut lower64 = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);
    // push r14
    stack::push(rt, r14);

    // mov r12, rdx
    rt.asm.mov(r12, rdx).unwrap();

    // mov r13b, [r12] -> dbits
    rt.asm.mov(r13b, ptr(r12)).unwrap();
    // add r12, 0x1
    rt.asm.add(r12, 0x1).unwrap();

    // movzx r8, [r12] -> dst
    rt.asm.movzx(r8, byte_ptr(r12)).unwrap();
    // add r12, 0x1
    rt.asm.add(r12, 0x1).unwrap();

    // xor r14b, r14b
    rt.asm.xor(r14b, r14b).unwrap();

    // mov al, [r12] -> sub
    rt.asm.mov(al, ptr(r12)).unwrap();
    // add r12, 0x1
    rt.asm.add(r12, 0x1).unwrap();
    // or r14b, al
    rt.asm.or(r14b, al).unwrap();

    // mov al, [r12] -> store
    rt.asm.mov(al, ptr(r12)).unwrap();
    // add r12, 0x1
    rt.asm.add(r12, 0x1).unwrap();
    // shl al, 0x1
    rt.asm.shl(al, 0x1).unwrap();
    // or r14b, al
    rt.asm.or(r14b, al).unwrap();

    // cmp r13b, ...
    rt.asm
        .cmp(r13b, rt.mapper.index(VMBits::Lower64) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower64).unwrap();
    // cmp r13b, ...
    rt.asm
        .cmp(r13b, rt.mapper.index(VMBits::Lower32) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower32).unwrap();
    // cmp r13b, ...
    rt.asm
        .cmp(r13b, rt.mapper.index(VMBits::Lower16) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower16).unwrap();
    // cmp r13b, ...
    rt.asm
        .cmp(r13b, rt.mapper.index(VMBits::Higher8) as i32)
        .unwrap();
    // je ...
    rt.asm.je(higher8).unwrap();

    rt.asm.set_label(&mut lower8).unwrap();
    {
        // lea rdx, [rcx + r8*8]
        rt.asm.lea(rdx, ptr(rcx + r8 * 8)).unwrap();
        // mov r8b, [r12]
        rt.asm.mov(r8b, ptr(r12)).unwrap();
        // add r12, 0x1
        rt.asm.add(r12, 0x1).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub8],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut higher8).unwrap();
    {
        // lea rdx, [rcx + r8*8 + 0x1]
        rt.asm.lea(rdx, ptr(rcx + r8 * 8 + 0x1)).unwrap();
        // mov r8b, [r12]
        rt.asm.mov(r8b, ptr(r12)).unwrap();
        // add r12, 0x1
        rt.asm.add(r12, 0x1).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub8],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut lower16).unwrap();
    {
        // lea rdx, [rcx + r8*8]
        rt.asm.lea(rdx, ptr(rcx + r8 * 8)).unwrap();
        // mov r8w, [r12]
        rt.asm.mov(r8w, ptr(r12)).unwrap();
        // add r12, 0x2
        rt.asm.add(r12, 0x2).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub16],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut lower32).unwrap();
    {
        // lea rdx, [rcx + r8*8]
        rt.asm.lea(rdx, ptr(rcx + r8 * 8)).unwrap();
        // mov r8d, [r12]
        rt.asm.mov(r8d, ptr(r12)).unwrap();
        // add r12, 0x4
        rt.asm.add(r12, 0x4).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub32],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut lower64).unwrap();
    {
        // lea rdx, [rcx + r8*8]
        rt.asm.lea(rdx, ptr(rcx + r8 * 8)).unwrap();
        // mov r8, [r12]
        rt.asm.mov(r8, ptr(r12)).unwrap();
        // add r12, 0x8
        rt.asm.add(r12, 0x8).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub64],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, r12
        rt.asm.mov(rax, r12).unwrap();

        // pop r14
        stack::pop(rt, r14);
        // pop r13
        stack::pop(rt, r13);
        // pop r12
        stack::pop(rt, r12);
        // ret
        stack::ret(rt);
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\arithmetic\addsubregmem.rs =====

use iced_x86::code_asm::{
    byte_ptr, ptr, r12, r13, r14, r14b, r8, r8b, r8d, r8w, r9, r9b, rax, rcx, rdx,
};

use crate::{
    runtime::{FnDef, Runtime},
    vm::{bytecode::VMBits, stack},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut lower8 = rt.asm.create_label();
    let mut higher8 = rt.asm.create_label();
    let mut lower16 = rt.asm.create_label();
    let mut lower32 = rt.asm.create_label();
    let mut lower64 = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);
    // push r14
    stack::push(rt, r14);

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();
    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // call ...
    stack::call(rt, rt.func_labels[&FnDef::ComputeAddress]);

    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // xor r14b, r14b
    rt.asm.xor(r14b, r14b).unwrap();

    // mov r8b, [r13] -> sub
    rt.asm.mov(r8b, ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();
    // or r14b, r8b
    rt.asm.or(r14b, r8b).unwrap();

    // mov r8b, [r13] -> store
    rt.asm.mov(r8b, ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();
    // shl r8b, 0x1
    rt.asm.shl(r8b, 0x1).unwrap();
    // or r14b, r8b
    rt.asm.or(r14b, r8b).unwrap();

    // mov r8b, [r13] -> dbits
    rt.asm.mov(r8b, ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();

    // movzx r9, [r13] -> dst
    rt.asm.movzx(r9, byte_ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();

    // cmp r8b, ...
    rt.asm
        .cmp(r8b, rt.mapper.index(VMBits::Lower64) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower64).unwrap();
    // cmp r8b, ...
    rt.asm
        .cmp(r8b, rt.mapper.index(VMBits::Lower32) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower32).unwrap();
    // cmp r8b, ...
    rt.asm
        .cmp(r8b, rt.mapper.index(VMBits::Lower16) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower16).unwrap();
    // cmp r8b, ...
    rt.asm
        .cmp(r8b, rt.mapper.index(VMBits::Higher8) as i32)
        .unwrap();
    // je ...
    rt.asm.je(higher8).unwrap();

    rt.asm.set_label(&mut lower8).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // lea rdx, [r12 + r9*8]
        rt.asm.lea(rdx, ptr(r12 + r9 * 8)).unwrap();
        // mov r8b, [rax]
        rt.asm.mov(r8b, ptr(rax)).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub8],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut higher8).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // lea rdx, [r12 + r9*8]
        rt.asm.lea(rdx, ptr(r12 + r9 * 8 + 0x1)).unwrap();
        // mov r8b, [rax]
        rt.asm.mov(r8b, ptr(rax)).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub8],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut lower16).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // lea rdx, [r12 + r9*8]
        rt.asm.lea(rdx, ptr(r12 + r9 * 8)).unwrap();
        // mov r8w, [rax]
        rt.asm.mov(r8w, ptr(rax)).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub16],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut lower32).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // lea rdx, [r12 + r9*8]
        rt.asm.lea(rdx, ptr(r12 + r9 * 8)).unwrap();
        // mov r8d, [rax]
        rt.asm.mov(r8d, ptr(rax)).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub32],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut lower64).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // lea rdx, [r12 + r9*8]
        rt.asm.lea(rdx, ptr(r12 + r9 * 8)).unwrap();
        // mov r8, [rax]
        rt.asm.mov(r8, ptr(rax)).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub64],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, r13
        rt.asm.mov(rax, r13).unwrap();

        // pop r14
        stack::pop(rt, r14);
        // pop r13
        stack::pop(rt, r13);
        // pop r12
        stack::pop(rt, r12);
        // ret
        stack::ret(rt);
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\arithmetic\addsubregreg.rs =====

use iced_x86::code_asm::{
    al, byte_ptr, ptr, r12, r13, r13b, r14, r14b, r15, r15b, r8, r8b, r8d, r8w, r9, r9b, rax, rcx,
    rdx,
};

use crate::{
    runtime::{FnDef, Runtime},

    vm::{bytecode::VMBits, stack},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut lower8 = rt.asm.create_label();
    let mut higher8 = rt.asm.create_label();
    let mut lower16 = rt.asm.create_label();
    let mut lower32 = rt.asm.create_label();
    let mut lower64 = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);
    // push r14
    stack::push(rt, r14);
    // push r15
    stack::push(rt, r15);

    // mov r12, rdx
    rt.asm.mov(r12, rdx).unwrap();

    // mov r13b, [r12] -> dbits
    rt.asm.mov(r13b, ptr(r12)).unwrap();
    // add r12, 0x1
    rt.asm.add(r12, 0x1).unwrap();

    // movzx r8, [r12] -> dst
    rt.asm.movzx(r8, byte_ptr(r12)).unwrap();
    // add r12, 0x1
    rt.asm.add(r12, 0x1).unwrap();

    // mov r14b, [r12] -> sbits
    rt.asm.mov(r14b, ptr(r12)).unwrap();
    // add r12, 0x1
    rt.asm.add(r12, 0x1).unwrap();

    // movzx r9, [r12] -> src
    rt.asm.movzx(r9, byte_ptr(r12)).unwrap();
    // add r12, 0x1
    rt.asm.add(r12, 0x1).unwrap();

    // xor r15b, r15b
    rt.asm.xor(r15b, r15b).unwrap();

    // mov al, [r12] -> sub
    rt.asm.mov(al, ptr(r12)).unwrap();
    // add r12, 0x1
    rt.asm.add(r12, 0x1).unwrap();
    // or r15b, al
    rt.asm.or(r15b, al).unwrap();

    // mov al, [r12] -> store
    rt.asm.mov(al, ptr(r12)).unwrap();
    // add r12, 0x1
    rt.asm.add(r12, 0x1).unwrap();
    // shl al, 0x1
    rt.asm.shl(al, 0x1).unwrap();
    // or r15b, al
    rt.asm.or(r15b, al).unwrap();

    // cmp r13b, ...
    rt.asm
        .cmp(r13b, rt.mapper.index(VMBits::Lower64) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower64).unwrap();
    // cmp r13b, ...
    rt.asm
        .cmp(r13b, rt.mapper.index(VMBits::Lower32) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower32).unwrap();
    // cmp r13b, ...
    rt.asm
        .cmp(r13b, rt.mapper.index(VMBits::Lower16) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower16).unwrap();
    // cmp r13b, ...
    rt.asm
        .cmp(r13b, rt.mapper.index(VMBits::Higher8) as i32)
        .unwrap();
    // je ...
    rt.asm.je(higher8).unwrap();

    rt.asm.set_label(&mut lower8).unwrap();
    {
        let mut is_lower = rt.asm.create_label();

        // lea rdx, [rcx + r8*8]
        rt.asm.lea(rdx, ptr(rcx + r8 * 8)).unwrap();

        // lea r8, [rcx + r9*8]
        rt.asm.lea(r8, ptr(rcx + r9 * 8)).unwrap();

        // cmp r14b, ...
        rt.asm
            .cmp(r14b, rt.mapper.index(VMBits::Higher8) as i32)
            .unwrap();
        // jne ...
        rt.asm.jne(is_lower).unwrap();

        // add r8, 0x1
        rt.asm.add(r8, 0x1).unwrap();

        rt.asm.set_label(&mut is_lower).unwrap();
        {
            // mov r8b, [r8]
            rt.asm.mov(r8b, ptr(r8)).unwrap();
            // mov r9b, r15b
            rt.asm.mov(r9b, r15b).unwrap();
            // call ...
            stack::call_with_label(
                rt,
                rt.func_labels[&FnDef::VmArithmeticAddSub8],
                &mut epilogue,
            );
        }
    }

    rt.asm.set_label(&mut higher8).unwrap();
    {
        let mut is_lower = rt.asm.create_label();

        // lea rdx, [rcx + r8*8 + 0x1]
        rt.asm.lea(rdx, ptr(rcx + r8 * 8 + 0x1)).unwrap();

        // lea r8, [rcx + r9*8]
        rt.asm.lea(r8, ptr(rcx + r9 * 8)).unwrap();

        // cmp r14b, ...
        rt.asm
            .cmp(r14b, rt.mapper.index(VMBits::Higher8) as i32)
            .unwrap();
        // jne ...
        rt.asm.jne(is_lower).unwrap();

        // add r8, 0x1
        rt.asm.add(r8, 0x1).unwrap();

        rt.asm.set_label(&mut is_lower).unwrap();
        {
            // mov r8b, [r8]
            rt.asm.mov(r8b, ptr(r8)).unwrap();
            // mov r9b, r15b
            rt.asm.mov(r9b, r15b).unwrap();
            // call ...
            stack::call_with_label(
                rt,
                rt.func_labels[&FnDef::VmArithmeticAddSub8],
                &mut epilogue,
            );
        }
    }

    rt.asm.set_label(&mut lower16).unwrap();
    {
        // lea rdx, [rcx + r8*8]
        rt.asm.lea(rdx, ptr(rcx + r8 * 8)).unwrap();
        // mov r8w, [rcx + r9*8]
        rt.asm.mov(r8w, ptr(rcx + r9 * 8)).unwrap();
        // mov r9b, r15b
        rt.asm.mov(r9b, r15b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub16],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut lower32).unwrap();
    {
        // lea rdx, [rcx + r8*8]
        rt.asm.lea(rdx, ptr(rcx + r8 * 8)).unwrap();
        // mov r8d, [rcx + r9*8]
        rt.asm.mov(r8d, ptr(rcx + r9 * 8)).unwrap();
        // mov r9b, r15b
        rt.asm.mov(r9b, r15b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub32],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut lower64).unwrap();
    {
        // lea rdx, [rcx + r8*8]
        rt.asm.lea(rdx, ptr(rcx + r8 * 8)).unwrap();
        // mov r8, [rcx + r9*8]
        rt.asm.mov(r8, ptr(rcx + r9 * 8)).unwrap();
        // mov r9b, r15b
        rt.asm.mov(r9b, r15b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub64],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, r12
        rt.asm.mov(rax, r12).unwrap();

        // pop r14
        stack::pop(rt, r15);
        // pop r14
        stack::pop(rt, r14);
        // pop r13
        stack::pop(rt, r13);
        // pop r12
        stack::pop(rt, r12);
        // ret
        stack::ret(rt);
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\arithmetic\flags.rs =====

use iced_x86::code_asm::{r8, rax, rcx, rdx};

use crate::{
    runtime::Runtime,

    vm::{
        bytecode::{VMFlag, VMReg},
        stack, utils,
    },
};

// void (unsigned long*, unsigned long)
pub fn build(rt: &mut Runtime) {
    // mov rax, [rcx + ...]
    utils::mov_reg_vreg_64(rt, rcx, VMReg::Flags, rax);

    const FLAG_MASK: u64 = (1 << VMFlag::Carry as u64)
        | (1 << VMFlag::Parity as u64)
        | (1 << VMFlag::Auxiliary as u64)
        | (1 << VMFlag::Zero as u64)
        | (1 << VMFlag::Sign as u64)
        | (1 << VMFlag::Overflow as u64);

    // mov r8, ...
    rt.asm.mov(r8, !FLAG_MASK).unwrap();
    // and rax, r8
    rt.asm.and(rax, r8).unwrap();

    // mov r8, ...
    rt.asm.mov(r8, FLAG_MASK).unwrap();
    // and rdx, r8
    rt.asm.and(rdx, r8).unwrap();
    // or rax, rdx
    rt.asm.or(rax, rdx).unwrap();

    // mov [rcx + ...], rax
    utils::mov_vreg_reg_64(rt, rcx, rax, VMReg::Flags);

    // ret
    stack::ret(rt);
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\arithmetic\mod.rs =====

pub mod addsub16;
pub mod addsub32;
pub mod addsub64;
pub mod addsub8;
pub mod addsubmemimm;
pub mod addsubmemreg;
pub mod addsubregimm;
pub mod addsubregmem;
pub mod addsubregreg;
pub mod flags;

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\branchimm.rs =====

use iced_x86::code_asm::{al, eax, ptr, r8, rax, rcx, rdx};

use crate::{
    runtime::Runtime,

    vm::{bytecode::VMReg, stack, utils},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut skip_ret = rt.asm.create_label();

    // mov al, [rdx] -> ret
    rt.asm.mov(al, ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // test al, al
    rt.asm.test(al, al).unwrap();
    // jz ...
    rt.asm.jz(skip_ret).unwrap();

    // sub [rcx + ...], 0x8
    utils::sub_vreg_imm_64(rt, rcx, 0x8, VMReg::Rsp);
    // mov r8, [rcx + ...]
    utils::mov_reg_vreg_64(rt, rcx, VMReg::Vra, r8);
    // mov rax, [rcx + ...]; mov [rax], r8
    utils::store_vreg_mem_64(rt, rcx, rax, r8, VMReg::Rsp);

    rt.asm.set_label(&mut skip_ret).unwrap();
    {
        // mov eax, [rdx] -> dst
        rt.asm.mov(eax, ptr(rdx)).unwrap();
        // add rdx, 0x4
        rt.asm.add(rdx, 0x4).unwrap();

        // add rax, [rcx + ...]
        utils::add_reg_vreg_64(rt, rcx, VMReg::VB, rax);

        // mov [rcx + ...], rax
        utils::mov_vreg_reg_64(rt, rcx, rax, VMReg::Vra);

        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();
        // ret
        stack::ret(rt);
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\branchmem.rs =====

use iced_x86::code_asm::{al, ptr, r12, r13, r8, rax, rcx, rdx};

use crate::{
    runtime::{FnDef, Runtime},
    vm::{bytecode::VMReg, stack, utils},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut skip_ret = rt.asm.create_label();

    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();
    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // mov al, [r13] -> ret
    rt.asm.mov(al, ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();

    // test al, al
    rt.asm.test(al, al).unwrap();
    // jz ...
    rt.asm.jz(skip_ret).unwrap();

    // sub [r12 + ...], 0x8
    utils::sub_vreg_imm_64(rt, r12, 0x8, VMReg::Rsp);
    // mov r8, [r12 + ...]
    utils::mov_reg_vreg_64(rt, r12, VMReg::Vra, r8);
    // mov rax, [r12 + ...]; mov [rax], r8
    utils::store_vreg_mem_64(rt, r12, rax, r8, VMReg::Rsp);

    rt.asm.set_label(&mut skip_ret).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // mov rdx, r13
        rt.asm.mov(rdx, r13).unwrap();
        // call ...
        stack::call(rt, rt.func_labels[&FnDef::ComputeAddress]);
        // mov r13, rdx
        rt.asm.mov(r13, rdx).unwrap();

        // mov rax, [rax]
        rt.asm.mov(rax, ptr(rax)).unwrap();

        // mov [r12 + ...], rax
        utils::mov_vreg_reg_64(rt, r12, rax, VMReg::Vra);

        // mov rax, r13
        rt.asm.mov(rax, r13).unwrap();
        // pop r13
        stack::pop(rt, r13);
        // pop r12
        stack::pop(rt, r12);
        // ret
        stack::ret(rt);
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\branchreg.rs =====

use iced_x86::code_asm::{al, byte_ptr, ptr, r8, rax, rcx, rdx};

use crate::{
    runtime::Runtime,
    vm::{bytecode::VMReg, stack, utils},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut skip_ret = rt.asm.create_label();

    // mov al, [rdx] -> ret
    rt.asm.mov(al, ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // test al, al
    rt.asm.test(al, al).unwrap();
    // jz ...
    rt.asm.jz(skip_ret).unwrap();

    // sub [rcx + ...], 0x8
    utils::sub_vreg_imm_64(rt, rcx, 0x8, VMReg::Rsp);
    // mov r8, [rcx + ...]
    utils::mov_reg_vreg_64(rt, rcx, VMReg::Vra, r8);
    // mov rax, [rcx + ...]; mov [rax], r8
    utils::store_vreg_mem_64(rt, rcx, rax, r8, VMReg::Rsp);

    rt.asm.set_label(&mut skip_ret).unwrap();
    {
        // movzx r8, [rdx] -> dst
        rt.asm.movzx(r8, byte_ptr(rdx)).unwrap();
        // add rdx, 0x1
        rt.asm.add(rdx, 0x1).unwrap();

        // mov rax, [rcx + rax * 8]
        rt.asm.mov(rax, ptr(rcx + r8 * 8)).unwrap();

        // mov [rcx + ...], rax
        utils::mov_vreg_reg_64(rt, rcx, rax, VMReg::Vra);

        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();
        // ret
        stack::ret(rt);
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\jcc.rs =====

use crate::vm::stack;
use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{VMLogic, VMReg, VMTest},
        utils,
    },
};
use iced_x86::code_asm::{
    al, byte_ptr, eax, ptr, r12, r12b, r13, r13d, r14, r14b, r8b, r8d, r9b, r9d, rax, rcx, rdx,
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();
    let mut condition_loop = rt.asm.create_label();
    let mut check_next = rt.asm.create_label();
    let mut handle_cmp = rt.asm.create_label();
    let mut handle_eq = rt.asm.create_label();
    let mut handle_neq = rt.asm.create_label();
    let mut is_or = rt.asm.create_label();
    let mut continue_loop = rt.asm.create_label();
    let mut skip_jump = rt.asm.create_label();

    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);
    // push r14
    stack::push(rt, r14);

    // mov r13d, [rcx + ...]
    utils::mov_reg_vreg_32(rt, rcx, VMReg::Flags, r13d);

    // mov al, [rdx] -> logic
    rt.asm.mov(al, ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // mov r14b, [rdx] -> number of conditions
    rt.asm.mov(r14b, ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // cmp al, ...
    rt.asm
        .cmp(al, rt.mapper.index(VMLogic::AND) as i32)
        .unwrap();
    // sete r12b
    rt.asm.sete(r12b).unwrap();

    rt.asm.set_label(&mut condition_loop).unwrap();
    {
        // test r14b, r14b
        rt.asm.test(r14b, r14b).unwrap();
        // jz ...
        rt.asm.jz(epilogue).unwrap();

        // movzx r8b, [rdx] -> cmp
        rt.asm.mov(r8b, ptr(rdx)).unwrap();
        // add rdx, 0x1
        rt.asm.add(rdx, 0x1).unwrap();

        // cmp r8b, ...
        rt.asm
            .cmp(r8b, rt.mapper.index(VMTest::CMP) as i32)
            .unwrap();
        // jz ...
        rt.asm.jz(handle_cmp).unwrap();
        // cmp r8b, ...
        rt.asm.cmp(r8b, rt.mapper.index(VMTest::EQ) as i32).unwrap();
        // je ...
        rt.asm.je(handle_eq).unwrap();
        // jmp ...
        rt.asm.jmp(handle_neq).unwrap();

        // Compares the bit in flags specified by the flag bit (lhs) with the set state (rhs)
        rt.asm.set_label(&mut handle_cmp).unwrap();
        {
            // movzx r8d, [rdx] -> lhs
            rt.asm.movzx(r8d, byte_ptr(rdx)).unwrap();
            // add rdx, 0x1
            rt.asm.add(rdx, 0x1).unwrap();

            // mov r9b, [rdx] -> rhs
            rt.asm.mov(r9b, ptr(rdx)).unwrap();
            // add rdx, 0x1
            rt.asm.add(rdx, 0x1).unwrap();

            // bt r13d, r8d
            rt.asm.bt(r13d, r8d).unwrap();
            // setc r8b
            rt.asm.setc(r8b).unwrap();
            // cmp r8b, r9b
            rt.asm.cmp(r8b, r9b).unwrap();
            // sete r8b
            rt.asm.sete(r8b).unwrap();
            // jmp ...
            rt.asm.jmp(check_next).unwrap();
        }

        // Checks if the bit in flags specified by the first flag bit (lhs) == the bit in flags specified by the second flag bit (rhs)
        rt.asm.set_label(&mut handle_eq).unwrap();
        {
            // movzx r8d, [rdx] -> lhs
            rt.asm.movzx(r8d, byte_ptr(rdx)).unwrap();
            // add rdx, 0x1
            rt.asm.add(rdx, 0x1).unwrap();

            // movzx r9d, [rdx] -> rhs
            rt.asm.movzx(r9d, byte_ptr(rdx)).unwrap();
            // add rdx, 0x1
            rt.asm.add(rdx, 0x1).unwrap();

            // bt r13d, r8d
            rt.asm.bt(r13d, r8d).unwrap();
            // setc r8b
            rt.asm.setc(r8b).unwrap();
            // bt r13d, r9d
            rt.asm.bt(r13d, r9d).unwrap();
            // setc r9b
            rt.asm.setc(r9b).unwrap();
            // cmp r8b, r9b
            rt.asm.cmp(r8b, r9b).unwrap();
            // sete r8b
            rt.asm.sete(r8b).unwrap();
            // jmp ...
            rt.asm.jmp(check_next).unwrap();
        }

        // Checks if the bit in flags specified by the first flag bit (lhs) != the bit in flags specified by the second flag bit (rhs)
        rt.asm.set_label(&mut handle_neq).unwrap();
        {
            // movzx r8d, [rdx] -> lhs
            rt.asm.movzx(r8d, byte_ptr(rdx)).unwrap();
            // add rdx, 0x1
            rt.asm.add(rdx, 0x1).unwrap();

            // movzx r9d, [rdx] -> rhs
            rt.asm.movzx(r9d, byte_ptr(rdx)).unwrap();
            // add rdx, 0x1
            rt.asm.add(rdx, 0x1).unwrap();

            // bt r13d, r8d
            rt.asm.bt(r13d, r8d).unwrap();
            // setc r8b
            rt.asm.setc(r8b).unwrap();
            // bt r13d, r9d
            rt.asm.bt(r13d, r9d).unwrap();
            // setc r9b
            rt.asm.setc(r9b).unwrap();
            // cmp r8b, r9b
            rt.asm.cmp(r8b, r9b).unwrap();
            // setne r8b
            rt.asm.setne(r8b).unwrap();
        }

        rt.asm.set_label(&mut check_next).unwrap();
        {
            // cmp al, ...
            rt.asm.cmp(al, rt.mapper.index(VMLogic::OR) as i32).unwrap();
            // je ...
            rt.asm.je(is_or).unwrap();
            // and r12b, r8b
            rt.asm.and(r12b, r8b).unwrap();
            // jmp ...
            rt.asm.jmp(continue_loop).unwrap();
        }

        rt.asm.set_label(&mut is_or).unwrap();
        {
            // or r12b, r8b
            rt.asm.or(r12b, r8b).unwrap();
        }

        rt.asm.set_label(&mut continue_loop).unwrap();
        {
            // dec r14b
            rt.asm.dec(r14b).unwrap();
            // jmp ...
            rt.asm.jmp(condition_loop).unwrap();
        }
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov eax, [rdx] -> dst
        rt.asm.mov(eax, ptr(rdx)).unwrap();
        // add rdx, 0x4
        rt.asm.add(rdx, 0x4).unwrap();

        // add rax, [rcx + ...]
        utils::add_reg_vreg_64(rt, rcx, VMReg::VB, rax);

        // test r12b, r12b
        rt.asm.test(r12b, r12b).unwrap();
        // jz ...
        rt.asm.jz(skip_jump).unwrap();

        // mov [rcx + ...], rax
        utils::mov_vreg_reg_64(rt, rcx, rax, VMReg::Vra);
    }

    rt.asm.set_label(&mut skip_jump).unwrap();
    {
        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();

        // pop r14
        stack::pop(rt, r14);
        // pop r13
        stack::pop(rt, r13);
        // pop r12
        stack::pop(rt, r12);
        // ret
        stack::ret(rt);
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\mod.rs =====

pub mod arithmetic;
pub mod branchimm;
pub mod branchmem;
pub mod branchreg;
pub mod jcc;
pub mod nop;
pub mod popreg;
pub mod pushimm;
pub mod pushpopregs;
pub mod pushreg;
pub mod setmemimm;
pub mod setmemreg;
pub mod setregimm;
pub mod setregmem;
pub mod setregreg;

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\nop.rs =====

use crate::runtime::Runtime;
use crate::vm::stack;

use iced_x86::code_asm::{rax, rdx};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // mov rax, rdx
    rt.asm.mov(rax, rdx).unwrap();
    // ret
    stack::ret(rt);
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\popreg.rs =====

use iced_x86::code_asm::{byte_ptr, ptr, r8, rax, rcx, rdx};

use crate::{
    runtime::Runtime,

    vm::{bytecode::VMReg, stack, utils},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // movzx r8, [rdx] -> dst
    rt.asm.movzx(r8, byte_ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // mov rax, [rcx + ...]; mov rax, [rax]
    utils::load_reg_mem_64(rt, rcx, rax, VMReg::Rsp, rax);
    // add [rcx + ...], 0x8
    utils::add_vreg_imm_64(rt, rcx, 0x8, VMReg::Rsp);
    // mov [rcx + r8*8], rax
    rt.asm.mov(ptr(rcx + r8 * 8), rax).unwrap();

    // mov rax, rdx
    rt.asm.mov(rax, rdx).unwrap();
    // ret
    stack::ret(rt);
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\pushimm.rs =====

use iced_x86::code_asm::{byte_ptr, ptr, r8, r8b, r8d, rax, rcx, rdx, word_ptr};

use crate::{
    runtime::Runtime,

    vm::{bytecode::VMReg, stack, utils},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut byte = rt.asm.create_label();
    let mut word = rt.asm.create_label();
    let mut dword = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // sub [rcx + ...], 0x8
    utils::sub_vreg_imm_64(rt, rcx, 0x8, VMReg::Rsp);

    // mov r8b, [rdx] -> size
    rt.asm.mov(r8b, byte_ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // cmp r8b, ...
    rt.asm.cmp(r8b, 0x4).unwrap();
    // je ...
    rt.asm.je(dword).unwrap();
    // cmp r8b, ...
    rt.asm.cmp(r8b, 0x2).unwrap();
    // je ...
    rt.asm.je(word).unwrap();

    rt.asm.set_label(&mut byte).unwrap();
    {
        // movsx r8, [rdx] -> src
        rt.asm.movsx(r8, byte_ptr(rdx)).unwrap();
        // add rdx, 0x1
        rt.asm.add(rdx, 0x1).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut word).unwrap();
    {
        // movsx r8, [rdx] -> src
        rt.asm.movsx(r8, word_ptr(rdx)).unwrap();
        // add rdx, 0x2
        rt.asm.add(rdx, 0x2).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut dword).unwrap();
    {
        // mov r8d, [rdx] -> src
        rt.asm.mov(r8d, ptr(rdx)).unwrap();
        // add rdx, 0x4
        rt.asm.add(rdx, 0x4).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, [rcx + ...]; mov [rax], r8
        utils::store_vreg_mem_64(rt, rcx, rax, r8, VMReg::Rsp);

        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();
        // ret
        stack::ret(rt);
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\pushpopregs.rs =====

use crate::{
    runtime::Runtime,

    vm::{bytecode::VMReg, stack, utils},
};
use iced_x86::code_asm::*;

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut register_loop = rt.asm.create_label();
    let mut is_pop = rt.asm.create_label();
    let mut continue_loop = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);

    // mov r12b, [rdx] -> pop
    rt.asm.mov(r12b, ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // movzx r13, byte [rdx] -> count
    rt.asm.movzx(r13, byte_ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    rt.asm.set_label(&mut register_loop).unwrap();
    {
        // test r13, r13
        rt.asm.test(r13, r13).unwrap();
        // jz ...
        rt.asm.jz(epilogue).unwrap();

        // movzx r8, byte [rdx]
        rt.asm.movzx(r8, byte_ptr(rdx)).unwrap();
        // inc rdx
        rt.asm.inc(rdx).unwrap();

        // test r12b, r12b
        rt.asm.test(r12b, r12b).unwrap();
        // jnz ...
        rt.asm.jnz(is_pop).unwrap();

        // sub [rcx + ...], 0x8
        utils::sub_vreg_imm_64(rt, rcx, 0x8, VMReg::Rsp);
        // mov r9, [rcx + r8*8]
        rt.asm.mov(r9, ptr(rcx + r8 * 8)).unwrap();
        // mov rax, [rcx + ...]; mov [rax], r9
        utils::store_vreg_mem_64(rt, rcx, rax, r9, VMReg::Rsp);
        // jmp ...
        rt.asm.jmp(continue_loop).unwrap();

        rt.asm.set_label(&mut is_pop).unwrap();
        {
            // mov rax, [rcx + ...]; mov rax, [rax]
            utils::load_reg_mem_64(rt, rcx, rax, VMReg::Rsp, rax);
            // add [rcx + ...], 0x8
            utils::add_vreg_imm_64(rt, rcx, 0x8, VMReg::Rsp);
            // mov [rcx + ...], rax
            rt.asm.mov(ptr(rcx + r8 * 8), rax).unwrap();
        }

        rt.asm.set_label(&mut continue_loop).unwrap();
        {
            // dec r13
            rt.asm.dec(r13).unwrap();
            // jmp ...
            rt.asm.jmp(register_loop).unwrap();
        }
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();

        // pop r13
        stack::pop(rt, r13);
        // pop r12
        stack::pop(rt, r12);
        // ret
        stack::ret(rt);
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\pushreg.rs =====

use iced_x86::code_asm::{byte_ptr, ptr, r8, rax, rcx, rdx};

use crate::{
    runtime::Runtime,

    vm::{bytecode::VMReg, stack, utils},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // movzx rax, [rdx] -> src
    rt.asm.movzx(rax, byte_ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // sub [rcx + ...], 0x8
    utils::sub_vreg_imm_64(rt, rcx, 0x8, VMReg::Rsp);
    // mov r8, [rcx + rax*8]
    rt.asm.mov(r8, ptr(rcx + rax * 8)).unwrap();
    // mov rax, [rcx + ...]; mov [rax], r8
    utils::store_vreg_mem_64(rt, rcx, rax, r8, VMReg::Rsp);

    // mov rax, rdx
    rt.asm.mov(rax, rdx).unwrap();
    // ret
    stack::ret(rt);
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\setmemimm.rs =====

use iced_x86::code_asm::{byte_ptr, r12, r13, rax, rcx, rdi, rdx, rsi};

use crate::{
    runtime::{FnDef, Runtime},

    vm::stack,
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);
    // push rsi
    stack::push(rt, rsi);
    // push rdi
    stack::push(rt, rdi);

    // mov r12, rdx
    rt.asm.mov(r12, rdx).unwrap();

    // mov rdx, r12
    rt.asm.mov(rdx, r12).unwrap();
    // call ...
    stack::call(rt, rt.func_labels[&FnDef::ComputeAddress]);

    // mov r12, rdx
    rt.asm.mov(r12, rdx).unwrap();

    // movzx r13, [r12] -> size
    rt.asm.movzx(r13, byte_ptr(r12)).unwrap();
    // add r12, 0x1
    rt.asm.add(r12, 0x1).unwrap();

    // mov rsi, r12
    rt.asm.mov(rsi, r12).unwrap();
    // mov rdi, rax
    rt.asm.mov(rdi, rax).unwrap();
    // mov rcx, r13
    rt.asm.mov(rcx, r13).unwrap();

    // cld
    rt.asm.cld().unwrap();

    // rep movsb
    rt.asm.rep().movsb().unwrap();

    // mov rax, rsi
    rt.asm.mov(rax, rsi).unwrap();

    // pop rdi
    stack::pop(rt, rdi);
    // pop rsi
    stack::pop(rt, rsi);
    // pop r13
    stack::pop(rt, r13);
    // pop r12
    stack::pop(rt, r12);
    // ret
    stack::ret(rt);
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\setmemreg.rs =====

use iced_x86::code_asm::{al, ax, bl, byte_ptr, eax, ptr, r12, r13, r14, r15, rax, rbx, rcx, rdx};

use crate::{
    runtime::{FnDef, Runtime},
    vm::bytecode::VMBits,
    vm::stack,
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut lower8 = rt.asm.create_label();
    let mut higher8 = rt.asm.create_label();
    let mut lower16 = rt.asm.create_label();
    let mut lower32 = rt.asm.create_label();
    let mut lower64 = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);
    // push r14
    stack::push(rt, r14);
    // push r15
    stack::push(rt, r15);
    // push rbx
    stack::push(rt, rbx);

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();
    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // mov bl, [r13] -> bits
    rt.asm.mov(bl, ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();

    // mov rcx, r12
    rt.asm.mov(rcx, r12).unwrap();
    // mov rdx, r13
    rt.asm.mov(rdx, r13).unwrap();
    // call ...
    stack::call(rt, rt.func_labels[&FnDef::ComputeAddress]);

    // mov r14, rax -> dst
    rt.asm.mov(r14, rax).unwrap();
    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // movzx r15, [r13] -> src
    rt.asm.movzx(r15, byte_ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();

    // cmp bl, ...
    rt.asm
        .cmp(bl, rt.mapper.index(VMBits::Lower64) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower64).unwrap();
    // cmp bl, ...
    rt.asm
        .cmp(bl, rt.mapper.index(VMBits::Lower32) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower32).unwrap();
    // cmp bl, ...
    rt.asm
        .cmp(bl, rt.mapper.index(VMBits::Lower16) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower16).unwrap();
    // cmp bl, ...
    rt.asm
        .cmp(bl, rt.mapper.index(VMBits::Higher8) as i32)
        .unwrap();
    // je ...
    rt.asm.je(higher8).unwrap();

    rt.asm.set_label(&mut lower8).unwrap();
    {
        // mov al, [r12 + r15*8]
        rt.asm.mov(al, ptr(r12 + r15 * 8)).unwrap();
        // mov [r14], al
        rt.asm.mov(ptr(r14), al).unwrap();
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut higher8).unwrap();
    {
        // mov al, [r12 + r15*8 + 0x1]
        rt.asm.mov(al, ptr(r12 + r15 * 8 + 0x1)).unwrap();
        // mov [r14], al
        rt.asm.mov(ptr(r14), al).unwrap();
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower16).unwrap();
    {
        // mov ax, [r12 + r15*8]
        rt.asm.mov(ax, ptr(r12 + r15 * 8)).unwrap();
        // mov [r14], ax
        rt.asm.mov(ptr(r14), ax).unwrap();
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower32).unwrap();
    {
        // mov eax, [r12 + r15*8]
        rt.asm.mov(eax, ptr(r12 + r15 * 8)).unwrap();
        // mov [r14], eax
        rt.asm.mov(ptr(r14), eax).unwrap();
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower64).unwrap();
    {
        // mov rax, [r12 + r15*8]
        rt.asm.mov(rax, ptr(r12 + r15 * 8)).unwrap();
        // mov [r14], rax
        rt.asm.mov(ptr(r14), rax).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, r13
        rt.asm.mov(rax, r13).unwrap();

        // pop rbx
        stack::pop(rt, rbx);
        // pop r15
        stack::pop(rt, r15);
        // pop r14
        stack::pop(rt, r14);
        // pop r13
        stack::pop(rt, r13);
        // pop r12
        stack::pop(rt, r12);
        // ret
        stack::ret(rt);
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\setregimm.rs =====

use iced_x86::code_asm::{al, byte_ptr, eax, ptr, r8, r9, rax, rcx, rdx, word_ptr};

use crate::{
    runtime::Runtime,
    vm::{bytecode::VMBits, stack},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut lower8 = rt.asm.create_label();
    let mut higher8 = rt.asm.create_label();
    let mut lower16 = rt.asm.create_label();
    let mut lower32 = rt.asm.create_label();
    let mut lower64 = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // mov al, [rdx] -> dbits
    rt.asm.mov(al, ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // movzx r8, [rdx] -> dst
    rt.asm.movzx(r8, byte_ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // cmp al, ...
    rt.asm
        .cmp(al, rt.mapper.index(VMBits::Lower64) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower64).unwrap();
    // cmp al, ...
    rt.asm
        .cmp(al, rt.mapper.index(VMBits::Lower32) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower32).unwrap();
    // cmp al, ...
    rt.asm
        .cmp(al, rt.mapper.index(VMBits::Lower16) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower16).unwrap();
    // cmp al, ...
    rt.asm
        .cmp(al, rt.mapper.index(VMBits::Higher8) as i32)
        .unwrap();
    // je ...
    rt.asm.je(higher8).unwrap();

    rt.asm.set_label(&mut lower8).unwrap();
    {
        // movzx rax, [rdx] -> src
        rt.asm.movzx(rax, byte_ptr(rdx)).unwrap();
        // add rdx, 0x1
        rt.asm.add(rdx, 0x1).unwrap();

        // mov r9, [rcx + r8*8]
        rt.asm.mov(r9, ptr(rcx + r8 * 8)).unwrap();
        // and r9, !0xFFFF
        rt.asm.and(r9, !0xFFi32).unwrap();
        // or r9, r8
        rt.asm.or(r9, rax).unwrap();
        // mov [rcx + r8*8], r9
        rt.asm.mov(ptr(rcx + r8 * 8), r9).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut higher8).unwrap();
    {
        // movzx rax, [rdx] -> src
        rt.asm.movzx(rax, byte_ptr(rdx)).unwrap();
        // add rdx, 0x1
        rt.asm.add(rdx, 0x1).unwrap();

        // mov r9, [rcx + r8*8]
        rt.asm.mov(r9, ptr(rcx + r8 * 8)).unwrap();
        // and r9, !0xFF00
        rt.asm.and(r9, !0xFF00i32).unwrap();
        // shl rax, 0x8
        rt.asm.shl(rax, 0x8).unwrap();
        // or r9, r8
        rt.asm.or(r9, rax).unwrap();
        // mov [rcx + r8*8], r9
        rt.asm.mov(ptr(rcx + r8 * 8), r9).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower16).unwrap();
    {
        // movzx rax, [rdx] -> src
        rt.asm.movzx(rax, word_ptr(rdx)).unwrap();
        // add rdx, 0x2
        rt.asm.add(rdx, 0x2).unwrap();

        // mov r9, [rcx + r8*8]
        rt.asm.mov(r9, ptr(rcx + r8 * 8)).unwrap();
        // and r9, !0xFFFF
        rt.asm.and(r9, !0xFFFFi32).unwrap();
        // or r9, rax
        rt.asm.or(r9, rax).unwrap();
        // mov [rcx + r8*8], r9
        rt.asm.mov(ptr(rcx + r8 * 8), r9).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower32).unwrap();
    {
        // mov eax, [rdx] -> src
        rt.asm.mov(eax, ptr(rdx)).unwrap();
        // add rdx, 0x4
        rt.asm.add(rdx, 0x4).unwrap();

        // mov [rcx + r8*8], rax
        rt.asm.mov(ptr(rcx + r8 * 8), rax).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower64).unwrap();
    {
        // mov rax, [rdx] -> src
        rt.asm.mov(rax, ptr(rdx)).unwrap();
        // add rdx, 0x8
        rt.asm.add(rdx, 0x8).unwrap();

        // mov [rcx + r8*8], rax
        rt.asm.mov(ptr(rcx + r8 * 8), rax).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();
        // ret
        stack::ret(rt);
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\setregmem.rs =====

use iced_x86::code_asm::{
    bh, bl, bx, byte_ptr, ptr, r12, r13, r14, r14b, r14d, r14w, r15, rax, rbx, rcx, rdx,
};

use crate::{
    runtime::{FnDef, Runtime},
    vm::bytecode::VMBits,
    vm::stack,
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut lower8 = rt.asm.create_label();
    let mut higher8 = rt.asm.create_label();
    let mut lower16 = rt.asm.create_label();
    let mut lower32 = rt.asm.create_label();
    let mut lower64 = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);
    // push r14
    stack::push(rt, r14);
    // push r15
    stack::push(rt, r15);
    // push rbx
    stack::push(rt, rbx);

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();
    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // mov bx, [r13] -> dbits | load
    rt.asm.mov(bx, ptr(r13)).unwrap();
    // add r13, 0x2
    rt.asm.add(r13, 0x2).unwrap();

    // movzx r15, [r13] -> dst
    rt.asm.movzx(r15, byte_ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();

    // mov rcx, r12
    rt.asm.mov(rcx, r12).unwrap();
    // mov rdx, r13
    rt.asm.mov(rdx, r13).unwrap();
    // call ...
    stack::call(rt, rt.func_labels[&FnDef::ComputeAddress]);

    // mov r14, rax -> src
    rt.asm.mov(r14, rax).unwrap();
    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // cmp bl, ...
    rt.asm
        .cmp(bl, rt.mapper.index(VMBits::Lower64) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower64).unwrap();
    // cmp bl, ...
    rt.asm
        .cmp(bl, rt.mapper.index(VMBits::Lower32) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower32).unwrap();
    // cmp bl, ...
    rt.asm
        .cmp(bl, rt.mapper.index(VMBits::Lower16) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower16).unwrap();
    // cmp bl, ...
    rt.asm
        .cmp(bl, rt.mapper.index(VMBits::Higher8) as i32)
        .unwrap();
    // je ...
    rt.asm.je(higher8).unwrap();

    rt.asm.set_label(&mut lower8).unwrap();
    {
        let mut skip = rt.asm.create_label();

        // test bh, bh
        rt.asm.test(bh, bh).unwrap();
        // jz ...
        rt.asm.jz(skip).unwrap();

        // mov r14b, [r14]
        rt.asm.mov(r14b, ptr(r14)).unwrap();

        rt.asm.set_label(&mut skip).unwrap();
        {
            // mov [r12 + r15*8], r14b
            rt.asm.mov(ptr(r12 + r15 * 8), r14b).unwrap();
            // jmp ...
            rt.asm.jmp(epilogue).unwrap();
        }
    }

    rt.asm.set_label(&mut higher8).unwrap();
    {
        let mut skip = rt.asm.create_label();

        // test bh, bh
        rt.asm.test(bh, bh).unwrap();
        // jz ...
        rt.asm.jz(skip).unwrap();

        // mov r14b, [r14]
        rt.asm.mov(r14b, ptr(r14)).unwrap();

        rt.asm.set_label(&mut skip).unwrap();
        {
            // mov [r12 + r15*8 + 0x1], r14b
            rt.asm.mov(ptr(r12 + r15 * 8 + 0x1), r14b).unwrap();
            // jmp ...
            rt.asm.jmp(epilogue).unwrap();
        }
    }

    rt.asm.set_label(&mut lower16).unwrap();
    {
        let mut skip = rt.asm.create_label();

        // test bh, bh
        rt.asm.test(bh, bh).unwrap();
        // jz ...
        rt.asm.jz(skip).unwrap();

        // mov r14w, [r14]
        rt.asm.mov(r14w, ptr(r14)).unwrap();

        rt.asm.set_label(&mut skip).unwrap();
        {
            // mov [r12 + r15*8], r14w
            rt.asm.mov(ptr(r12 + r15 * 8), r14w).unwrap();
            // jmp ...
            rt.asm.jmp(epilogue).unwrap();
        }
    }

    rt.asm.set_label(&mut lower32).unwrap();
    {
        let mut skip = rt.asm.create_label();

        // test bh, bh
        rt.asm.test(bh, bh).unwrap();
        // jz ...
        rt.asm.jz(skip).unwrap();

        // mov r14d, [r14]
        rt.asm.mov(r14d, ptr(r14)).unwrap();

        rt.asm.set_label(&mut skip).unwrap();
        {
            // mov [r12 + r15*8], r14d
            rt.asm.mov(ptr(r12 + r15 * 8), r14).unwrap();
            // jmp ...
            rt.asm.jmp(epilogue).unwrap();
        }
    }

    rt.asm.set_label(&mut lower64).unwrap();
    {
        let mut skip = rt.asm.create_label();

        // test bh, bh
        rt.asm.test(bh, bh).unwrap();
        // jz ...
        rt.asm.jz(skip).unwrap();

        // mov r14, [r14]
        rt.asm.mov(r14, ptr(r14)).unwrap();

        rt.asm.set_label(&mut skip).unwrap();
        {
            // mov [r12 + r15*8], r14
            rt.asm.mov(ptr(r12 + r15 * 8), r14).unwrap();
        }
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, r13
        rt.asm.mov(rax, r13).unwrap();

        // pop rbx
        stack::pop(rt, rbx);
        // pop r15
        stack::pop(rt, r15);
        // pop r14
        stack::pop(rt, r14);
        // pop r13
        stack::pop(rt, r13);
        // pop r12
        stack::pop(rt, r12);
        // ret
        stack::ret(rt);
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\handlers\setregreg.rs =====

use iced_x86::code_asm::{
    ax, byte_ptr, eax, ptr, r12, r12b, r13, r13b, r8, r9, r9b, rax, rcx, rdx,
};

use crate::{
    runtime::Runtime,
    vm::{bytecode::VMBits, stack},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut lower8 = rt.asm.create_label();
    let mut higher8 = rt.asm.create_label();
    let mut lower16 = rt.asm.create_label();
    let mut lower32 = rt.asm.create_label();
    let mut lower64 = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);

    // mov r12b, [rdx] -> dbits
    rt.asm.mov(r12b, ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // movzx r8, [rdx] -> dst
    rt.asm.movzx(r8, byte_ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // mov r13b, [rdx] -> sbits
    rt.asm.mov(r13b, ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // movzx r9, [rdx] -> src
    rt.asm.movzx(r9, byte_ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // cmp r12b, ...
    rt.asm
        .cmp(r12b, rt.mapper.index(VMBits::Lower64) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower64).unwrap();
    // cmp r12b, ...
    rt.asm
        .cmp(r12b, rt.mapper.index(VMBits::Lower32) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower32).unwrap();
    // cmp r12b, ...
    rt.asm
        .cmp(r12b, rt.mapper.index(VMBits::Lower16) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower16).unwrap();
    // cmp r12b, ...
    rt.asm
        .cmp(r12b, rt.mapper.index(VMBits::Higher8) as i32)
        .unwrap();
    // je ...
    rt.asm.je(higher8).unwrap();

    rt.asm.set_label(&mut lower8).unwrap();
    {
        let mut is_lower = rt.asm.create_label();

        // lea r9, [rcx + r9*8]
        rt.asm.lea(r9, ptr(rcx + r9 * 8)).unwrap();

        // cmp r13b, ...
        rt.asm
            .cmp(r13b, rt.mapper.index(VMBits::Higher8) as i32)
            .unwrap();
        // jne ...
        rt.asm.jne(is_lower).unwrap();

        // add r9, 0x1
        rt.asm.add(r9, 0x1).unwrap();

        rt.asm.set_label(&mut is_lower).unwrap();
        {
            // mov r9b, [r9]
            rt.asm.mov(r9b, ptr(r9)).unwrap();
            // mov [rcx + r8*8], r9b
            rt.asm.mov(ptr(rcx + r8 * 8), r9b).unwrap();
            // jmp ...
            rt.asm.jmp(epilogue).unwrap();
        }
    }

    rt.asm.set_label(&mut higher8).unwrap();
    {
        let mut is_lower = rt.asm.create_label();

        // lea r9, [rcx + r9*8]
        rt.asm.lea(r9, ptr(rcx + r9 * 8)).unwrap();

        // cmp r13b, ...
        rt.asm
            .cmp(r13b, rt.mapper.index(VMBits::Higher8) as i32)
            .unwrap();
        // jne ...
        rt.asm.jne(is_lower).unwrap();

        // add r9, 0x1
        rt.asm.add(r9, 0x1).unwrap();

        rt.asm.set_label(&mut is_lower).unwrap();
        {
            // mov r9b, [r9]
            rt.asm.mov(r9b, ptr(r9)).unwrap();
            // mov [rcx + r8*8], r9b
            rt.asm.mov(ptr(rcx + r8 * 8 + 0x1), r9b).unwrap();
            // jmp ...
            rt.asm.jmp(epilogue).unwrap();
        }
    }

    rt.asm.set_label(&mut lower16).unwrap();
    {
        // mov ax, [rcx + r9*8] -> src
        rt.asm.mov(ax, ptr(rcx + r9 * 8)).unwrap();
        // mov [rcx + r8*8], ax
        rt.asm.mov(ptr(rcx + r8 * 8), ax).unwrap();
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower32).unwrap();
    {
        // mov eax, [rcx + r9*8] -> src
        rt.asm.mov(eax, ptr(rcx + r9 * 8)).unwrap();
        // mov [rcx + r8*8], rax
        rt.asm.mov(ptr(rcx + r8 * 8), rax).unwrap();
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower64).unwrap();
    {
        // mov rax, [rcx + r9*8] -> src
        rt.asm.mov(rax, ptr(rcx + r9 * 8)).unwrap();
        // mov [rcx + r8*8], rax
        rt.asm.mov(ptr(rcx + r8 * 8), rax).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();

        // pop r13
        stack::pop(rt, r13);
        // pop r12
        stack::pop(rt, r12);
        // ret
        stack::ret(rt);
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\mod.rs =====

pub mod bytecode;
pub mod cleanup;
pub mod crypt;
pub mod dispatch;
pub mod entry;
pub mod exit;
pub mod ginit;
pub mod handlers;
pub mod stack;
pub mod tinit;
pub mod utils;
pub mod veh;

use crate::vm::bytecode::VMReg;
use iced_x86::code_asm::{
    r10, r11, r13, r14, r15, r8, r9, rax, rbp, rbx, rcx, rdi, rdx, rsi, AsmRegister64,
};

const VREG_TO_REG: &[(VMReg, AsmRegister64)] = &[
    (VMReg::Rax, rax),
    (VMReg::Rcx, rcx),
    (VMReg::Rdx, rdx),
    (VMReg::Rbx, rbx),
    (VMReg::Rbp, rbp),
    (VMReg::Rsi, rsi),
    (VMReg::Rdi, rdi),
    (VMReg::R8, r8),
    (VMReg::R9, r9),
    (VMReg::R10, r10),
    (VMReg::R11, r11),
    (VMReg::R13, r13),
    (VMReg::R14, r14),
    (VMReg::R15, r15),
];

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\stack.rs =====

use iced_x86::code_asm::{
    al, asm_traits::CodeAsmJmp, ptr, qword_ptr, r10, r10d, r11, r11b, r11d, rax, AsmRegister64,
    CodeAssembler, CodeLabel,
};

use crate::runtime::{DataDef, Runtime};

pub fn push(rt: &mut Runtime, src: AsmRegister64) {
    // mov r11d, [...]
    rt.asm
        .mov(r11d, ptr(rt.data_labels[&DataDef::VmStackTlsIndex]))
        .unwrap();
    // sub gs:[0x1480 + r11*8], 0x8
    rt.asm.sub(qword_ptr(0x1480 + r11 * 8).gs(), 0x8).unwrap();
    // mov r11, gs:[0x1480 + r11*8]
    rt.asm.mov(r11, ptr(0x1480 + r11 * 8).gs()).unwrap();
    // mov [r11], ...
    rt.asm.mov(ptr(r11), src).unwrap();
}

pub fn pop(rt: &mut Runtime, dst: AsmRegister64) {
    // mov r11d, [...]
    rt.asm
        .mov(r11d, ptr(rt.data_labels[&DataDef::VmStackTlsIndex]))
        .unwrap();
    // add gs:[0x1480 + r11*8], 0x8
    rt.asm.add(qword_ptr(0x1480 + r11 * 8).gs(), 0x8).unwrap();
    // mov r11, gs:[0x1480 + r11*8]
    rt.asm.mov(r11, ptr(0x1480 + r11 * 8).gs()).unwrap();
    // mov ..., [r11 - 0x8]
    rt.asm.mov(dst, ptr(r11 - 0x8)).unwrap();
}

// NOTE: Hopefully this does not cause problems :D
pub fn pushfq(rt: &mut Runtime) {
    // mov r10, rax
    rt.asm.mov(r10, rax).unwrap();

    // lahf
    rt.asm.lahf().unwrap();
    // seto r11b
    rt.asm.seto(r11b).unwrap();

    // movzx r11, r11b
    rt.asm.movzx(r11, r11b).unwrap();
    // shl r11, 0xb
    rt.asm.shl(r11, 0xb).unwrap();

    // shr rax, 0x8
    rt.asm.shr(rax, 0x8).unwrap();
    // movzx rax, al
    rt.asm.movzx(rax, al).unwrap();
    // or r11, rax
    rt.asm.or(r11, rax).unwrap();

    // mov rax, r10
    rt.asm.mov(rax, r10).unwrap();

    // mov r10d, [...]
    rt.asm
        .mov(r10d, ptr(rt.data_labels[&DataDef::VmStackTlsIndex]))
        .unwrap();
    // sub gs:[0x1480 + r10*8], 0x8
    rt.asm.sub(qword_ptr(0x1480 + r10 * 8).gs(), 0x8).unwrap();
    // mov r10, gs:[0x1480 + r10*8]
    rt.asm.mov(r10, ptr(0x1480 + r10 * 8).gs()).unwrap();
    // mov [r10], r11
    rt.asm.mov(ptr(r10), r11).unwrap();
}

pub fn call<T>(rt: &mut Runtime, target: T)
where
    CodeAssembler: CodeAsmJmp<T>,
{
    let mut ret = rt.asm.create_label();
    call_with_label(rt, target, &mut ret);
    rt.asm.set_label(&mut ret).unwrap();
}

pub fn call_with_label<T>(rt: &mut Runtime, target: T, ret: &CodeLabel)
where
    CodeAssembler: CodeAsmJmp<T>,
{
    // lea r10, [...]
    rt.asm.lea(r10, ptr(*ret)).unwrap();
    // push r10
    push(rt, r10);
    // jmp ...
    rt.asm.jmp(target).unwrap();
}

pub fn ret(rt: &mut Runtime) {
    // pop r10
    pop(rt, r10);
    // jmp r10
    rt.asm.jmp(r10).unwrap();
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\tinit.rs =====

use iced_x86::code_asm::{ecx, ptr, r12, r13, r8, rax, rcx, rdi, rdx, rsi, rsp};

use crate::{
    mapper::Mappable,
    runtime::{DataDef, Runtime, StringDef},
    vm::bytecode::VMReg,
    VM_STACK_SIZE,
};

pub fn build(rt: &mut Runtime) {
    // push r12
    rt.asm.push(r12).unwrap();
    // push r13
    rt.asm.push(r13).unwrap();
    // push rsi
    rt.asm.push(rsi).unwrap();
    // push rdi
    rt.asm.push(rdi).unwrap();

    // sub rsp, 0x28
    rt.asm.sub(rsp, 0x28).unwrap();

    // lea rcx, [...]; lea rdx, [...]; call ...
    rt.get_proc_address(StringDef::KERNEL32, StringDef::GetProcessHeap);
    // call rax
    rt.asm.call(rax).unwrap();
    // mov r12, rax
    rt.asm.mov(r12, rax).unwrap();

    // lea rcx, [...]; lea rdx, [...]; call ...
    rt.get_proc_address(StringDef::Ntdll, StringDef::RtlAllocateHeap);
    // mov r13, rax
    rt.asm.mov(r13, rax).unwrap();

    // mov rcx, r12
    rt.asm.mov(rcx, r12).unwrap();
    // mov rdx, 0x00000008 -> HEAP_ZERO_MEMORY
    rt.asm.mov(rdx, 0x00000008u64).unwrap();
    // mov r8, ...
    rt.asm.mov(r8, (VMReg::COUNT * 8) as u64).unwrap();
    // call r13
    rt.asm.call(r13).unwrap();

    // mov ecx, [...]
    rt.asm
        .mov(ecx, ptr(rt.data_labels[&DataDef::VmStateTlsIndex]))
        .unwrap();
    // mov [0x1480 + rcx*8], rax
    rt.asm.mov(ptr(0x1480 + rcx * 8).gs(), rax).unwrap();

    // mov rcx, r12
    rt.asm.mov(rcx, r12).unwrap();
    // mov rdx, 0x00000008 -> HEAP_ZERO_MEMORY
    rt.asm.mov(rdx, 0x00000008u64).unwrap();
    // mov r8, ...
    rt.asm.mov(r8, VM_STACK_SIZE).unwrap();
    // call r13
    rt.asm.call(r13).unwrap();

    // add rax, ...
    rt.asm.add(rax, VM_STACK_SIZE as i32).unwrap();

    // mov ecx, [...]
    rt.asm
        .mov(ecx, ptr(rt.data_labels[&DataDef::VmStackTlsIndex]))
        .unwrap();
    // mov [0x1480 + rcx*8], rax
    rt.asm.mov(ptr(0x1480 + rcx * 8).gs(), rax).unwrap();

    // lea rcx, [...]; lea rdx, [...]; call ...
    rt.get_proc_address(StringDef::Ntdll, StringDef::RtlFlsSetValue);
    // mov ecx, [...]
    rt.asm
        .mov(ecx, ptr(rt.data_labels[&DataDef::VmCleanupFlsIndex]))
        .unwrap();
    // mov rdx, 0x1
    rt.asm.mov(rdx, 0x1u64).unwrap();
    // call rax
    rt.asm.call(rax).unwrap();

    // add rsp, 0x28
    rt.asm.add(rsp, 0x28).unwrap();

    // pop rdi
    rt.asm.pop(rdi).unwrap();
    // pop rsi
    rt.asm.pop(rsi).unwrap();
    // pop r13
    rt.asm.pop(r13).unwrap();
    // pop r12
    rt.asm.pop(r12).unwrap();
    // ret
    rt.asm.ret().unwrap();
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\utils\compute_address.rs =====

use iced_x86::code_asm::{byte_ptr, dword_ptr, ptr, r8, r9, rax, rcx, rdx};

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{VMReg, VMSeg},
        stack,
    },
};

// unsigned long, unsigned long (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut add_base = rt.asm.create_label();
    let mut check_index = rt.asm.create_label();
    let mut add_displ = rt.asm.create_label();
    let mut add_seg = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // xor rax, rax
    rt.asm.xor(rax, rax).unwrap();

    // movzx r8, [rdx] -> base
    rt.asm.movzx(r8, byte_ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // cmp r8, ...
    rt.asm.cmp(r8, rt.mapper.index(VMReg::None) as i32).unwrap();
    // je ...
    rt.asm.je(check_index).unwrap();

    rt.asm.set_label(&mut add_base).unwrap();
    {
        // add rax, [rcx + r8*8]
        rt.asm.add(rax, ptr(rcx + r8 * 8)).unwrap();
    }

    rt.asm.set_label(&mut check_index).unwrap();
    {
        // movzx r8, [rdx] -> index
        rt.asm.movzx(r8, byte_ptr(rdx)).unwrap();
        // add rdx, 0x1
        rt.asm.add(rdx, 0x1).unwrap();

        // movzx r9, [rdx] -> scale
        rt.asm.movzx(r9, byte_ptr(rdx)).unwrap();
        // add rdx, 0x1
        rt.asm.add(rdx, 0x1).unwrap();

        // cmp r8, ...
        rt.asm.cmp(r8, rt.mapper.index(VMReg::None) as i32).unwrap();
        // je ...
        rt.asm.je(add_displ).unwrap();
    }

    // mov r8, [rcx + r8*8]
    rt.asm.mov(r8, ptr(rcx + r8 * 8)).unwrap();
    // imul r8, r9
    rt.asm.imul_2(r8, r9).unwrap();
    // add rax, r8
    rt.asm.add(rax, r8).unwrap();

    rt.asm.set_label(&mut add_displ).unwrap();
    {
        // movsxd r8, [rdx] -> displ
        rt.asm.movsxd(r8, dword_ptr(rdx)).unwrap();
        // add rdx, 0x4
        rt.asm.add(rdx, 0x4).unwrap();
        // add rax, r8
        rt.asm.add(rax, r8).unwrap();
    }

    // movzx r8, [rdx] -> seg
    rt.asm.movzx(r8, byte_ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // cmp r8, ...
    rt.asm.cmp(r8, rt.mapper.index(VMSeg::None) as i32).unwrap();
    // je ...
    rt.asm.je(epilogue).unwrap();

    rt.asm.set_label(&mut add_seg).unwrap();
    {
        // add rax, gs:[0x30] -> NT_TIB *TEB->NT_TIB.Self
        rt.asm.add(rax, ptr(0x30).gs()).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // ret
        stack::ret(rt);
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\utils\mod.rs =====

pub mod compute_address;

use crate::{runtime::Runtime, vm::bytecode::VMReg};
use iced_x86::code_asm::{ptr, qword_ptr, AsmRegister32, AsmRegister64};

pub fn mov_reg_vreg_64(rt: &mut Runtime, src: AsmRegister64, from: VMReg, to: AsmRegister64) {
    // mov ..., [...]
    rt.asm
        .mov(to, ptr(src + rt.mapper.index(from) * 8))
        .unwrap();
}

pub fn mov_reg_vreg_32(rt: &mut Runtime, src: AsmRegister64, from: VMReg, to: AsmRegister32) {
    // mov ..., [...]
    rt.asm
        .mov(to, ptr(src + rt.mapper.index(from) * 8))
        .unwrap();
}

pub fn mov_vreg_reg_64(rt: &mut Runtime, src: AsmRegister64, from: AsmRegister64, to: VMReg) {
    // mov [...], ...
    rt.asm
        .mov(ptr(src + rt.mapper.index(to) * 8), from)
        .unwrap();
}

pub fn add_vreg_reg_64(rt: &mut Runtime, src: AsmRegister64, from: AsmRegister64, to: VMReg) {
    // add [...], ...
    rt.asm
        .add(ptr(src + rt.mapper.index(to) * 8), from)
        .unwrap();
}

pub fn add_vreg_imm_64(rt: &mut Runtime, src: AsmRegister64, from: i32, to: VMReg) {
    // add [...], ...
    rt.asm
        .add(qword_ptr(src + rt.mapper.index(to) * 8), from)
        .unwrap();
}

pub fn add_reg_vreg_64(rt: &mut Runtime, src: AsmRegister64, from: VMReg, to: AsmRegister64) {
    // add ..., [...]
    rt.asm
        .add(to, ptr(src + rt.mapper.index(from) * 8))
        .unwrap();
}

pub fn sub_vreg_reg_64(rt: &mut Runtime, src: AsmRegister64, from: AsmRegister64, to: VMReg) {
    // sub [...], ...
    rt.asm
        .sub(ptr(src + rt.mapper.index(to) * 8), from)
        .unwrap();
}

pub fn sub_vreg_imm_64(rt: &mut Runtime, src: AsmRegister64, from: i32, to: VMReg) {
    // sub [...], ...
    rt.asm
        .sub(qword_ptr(src + rt.mapper.index(to) * 8), from)
        .unwrap();
}

pub fn sub_reg_vreg_64(rt: &mut Runtime, src: AsmRegister64, from: VMReg, to: AsmRegister64) {
    // sub ..., [...]
    rt.asm
        .sub(to, ptr(src + rt.mapper.index(from) * 8))
        .unwrap();
}

pub fn cmp_vreg_reg_64(rt: &mut Runtime, src: AsmRegister64, a: VMReg, b: AsmRegister64) {
    // cmp [...], ...
    rt.asm.cmp(ptr(src + rt.mapper.index(a) * 8), b).unwrap();
}

pub fn store_vreg_mem_64(
    rt: &mut Runtime,
    src: AsmRegister64,
    with: AsmRegister64,
    from: AsmRegister64,
    to: VMReg,
) {
    // mov ..., [...]
    rt.asm
        .mov(with, ptr(src + rt.mapper.index(to) * 8))
        .unwrap();
    // mov [...], ...
    rt.asm.mov(ptr(with), from).unwrap();
}

pub fn load_reg_mem_64(
    rt: &mut Runtime,
    src: AsmRegister64,
    with: AsmRegister64,
    from: VMReg,
    to: AsmRegister64,
) {
    // mov ..., [...]
    rt.asm
        .mov(with, ptr(src + rt.mapper.index(from) * 8))
        .unwrap();
    // mov ..., [...]
    rt.asm.mov(to, ptr(with)).unwrap();
}

pub fn push_vreg_64(rt: &mut Runtime, src: AsmRegister64, from: VMReg) {
    // push [...]
    rt.asm
        .push(qword_ptr(src + rt.mapper.index(from) * 8))
        .unwrap();
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\runtime\src\vm\veh.rs =====

use iced_x86::code_asm::{
    al, byte_ptr, cl, eax, ecx, ptr, qword_ptr, r12, r13, r14, r8, r9b, rax, rcx, rdx, rsp,
};

use crate::{
    runtime::{BoolDef, DataDef, FnDef, Runtime, StringDef},
    vm::{bytecode::VMReg, stack, utils},
};

pub fn initialize(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // sub rsp, 0x28
    rt.asm.sub(rsp, 0x28).unwrap();

    // mov al, [...]
    rt.asm
        .mov(al, ptr(rt.bool_labels[&BoolDef::VmHasVeh]))
        .unwrap();
    // test al, al
    rt.asm.test(al, al).unwrap();
    // jnz ...
    rt.asm.jnz(epilogue).unwrap();

    // lea rcx, [...]; lea rdx, [...], call ...
    rt.get_proc_address(StringDef::Ntdll, StringDef::RtlAddVectoredExceptionHandler);

    // mov rcx, 0x1
    rt.asm.mov(rcx, 0x1u64).unwrap();
    // lea rdx, [...]
    rt.asm
        .lea(rdx, ptr(rt.func_labels[&FnDef::VmVehHandler]))
        .unwrap();
    // call rax
    rt.asm.call(rax).unwrap();

    // mov [...], 0x1
    rt.asm
        .mov(byte_ptr(rt.bool_labels[&BoolDef::VmHasVeh]), 0x1)
        .unwrap();

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // add rsp, 0x28
        rt.asm.add(rsp, 0x28).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}

const VM_TO_CONTEXT: &[(VMReg, i32)] = &[
    (VMReg::Rax, 0x78),
    (VMReg::Rcx, 0x80),
    (VMReg::Rdx, 0x88),
    (VMReg::Rbx, 0x90),
    (VMReg::Rsp, 0x98),
    (VMReg::Rbp, 0xA0),
    (VMReg::Rsi, 0xA8),
    (VMReg::Rdi, 0xB0),
    (VMReg::R8, 0xB8),
    (VMReg::R9, 0xC0),
    (VMReg::R10, 0xC8),
    (VMReg::R11, 0xD0),
    (VMReg::R12, 0xD8),
    (VMReg::R13, 0xE0),
    (VMReg::R14, 0xE8),
    (VMReg::R15, 0xF0),
    (VMReg::Vea, 0xF8),
    (VMReg::Flags, 0x44),
];

pub const TRAP_MAGIC: u8 = 0x8E;

// long (*EXCEPTION_POINTERS)
pub fn handler(rt: &mut Runtime) {
    let mut check_range = rt.asm.create_label();
    let mut handle_trap = rt.asm.create_label();
    let mut continue_search = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r12
    rt.asm.push(r12).unwrap();
    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();

    // sub rsp, 0x28
    rt.asm.sub(rsp, 0x28).unwrap();

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();
    // mov r13, [r12] -> EXCEPTION_RECORD *EXCEPTION_POINTERS->ExceptionRecord
    rt.asm.mov(r13, ptr(r12)).unwrap();
    // mov r14, [r12 + 0x8] -> CONTEXT *EXCEPTION_POINTERS->ContextRecord
    rt.asm.mov(r14, ptr(r12 + 0x8)).unwrap();

    // mov eax, [r13] -> DWORD EXCEPTION_RECORD->ExceptionCode
    rt.asm.mov(eax, ptr(r13)).unwrap();
    // cmp eax, 0xC0000005
    rt.asm.cmp(eax, 0xC0000005u32).unwrap();
    // jne ...
    rt.asm.jne(check_range).unwrap();

    // mov rax, [r13 + 0x28] -> EXCEPTION_RECORD->ExceptionInformation[1]
    rt.asm.mov(rax, ptr(r13 + 0x28)).unwrap();

    // mov ecx, eax
    rt.asm.mov(ecx, eax).unwrap();
    // shr ecx, 0x18
    rt.asm.shr(ecx, 0x18).unwrap();
    // cmp cl, ...
    rt.asm.cmp(cl, TRAP_MAGIC as u32).unwrap();
    // je ...
    rt.asm.je(handle_trap).unwrap();

    rt.asm.set_label(&mut check_range).unwrap();
    {
        // mov rax, [r13 + 0x10] -> PVOID EXCEPTION_RECORD->ExceptionAddress
        rt.asm.mov(rax, ptr(r13 + 0x10)).unwrap();

        // lea rcx, [...]
        rt.asm
            .lea(rcx, ptr(rt.data_labels[&DataDef::VehStart]))
            .unwrap();
        // cmp rax, rcx
        rt.asm.cmp(rax, rcx).unwrap();
        // jb ...
        rt.asm.jb(continue_search).unwrap();

        // lea rcx, [...]
        rt.asm
            .lea(rcx, ptr(rt.data_labels[&DataDef::VehEnd]))
            .unwrap();
        // cmp rax, rcx
        rt.asm.cmp(rax, rcx).unwrap();
        // jae ...
        rt.asm.jae(continue_search).unwrap();
    }

    // mov eax, [...]
    rt.asm
        .mov(eax, ptr(rt.data_labels[&DataDef::VmStateTlsIndex]))
        .unwrap();
    // mov rax, gs:[0x1480 + rax*8]
    rt.asm.mov(rax, ptr(0x1480 + rax * 8).gs()).unwrap();

    for (vreg, offset) in VM_TO_CONTEXT {
        // mov rcx, [rax + ...]
        utils::mov_reg_vreg_64(rt, rax, *vreg, rcx);

        if *vreg == VMReg::Flags {
            // mov [r14 + ...], ecx
            rt.asm.mov(ptr(r14 + *offset), ecx).unwrap();
        } else {
            // mov [r14 + ...], rcx
            rt.asm.mov(ptr(r14 + *offset), rcx).unwrap();
        }

        if *vreg == VMReg::Vea {
            // mov [r13 + 0x10], rcx -> PVOID EXCEPTION_RECORD->ExceptionAddress
            rt.asm.mov(ptr(r13 + 0x10), rcx).unwrap();
        }
    }

    // mov rcx, [rax + ...]
    utils::mov_reg_vreg_64(rt, rax, VMReg::Vbp, rcx);
    // mov rdx, [rax + ...]
    utils::mov_reg_vreg_64(rt, rax, VMReg::Vbl, rdx);
    // mov r8, [r14 + ...]
    utils::mov_reg_vreg_64(rt, r12, VMReg::Vsk, r8);
    // xor r9b, r9b
    rt.asm.xor(r9b, r9b).unwrap();
    // call ...
    stack::call(rt, rt.func_labels[&FnDef::VmCrypt]);

    // mov rax, -0x1 -> EXCEPTION_CONTINUE_EXECUTION
    rt.asm.mov(rax, -0x1i64 as u64).unwrap();
    // jmp ...
    rt.asm.jmp(epilogue).unwrap();

    rt.asm.set_label(&mut handle_trap).unwrap();
    {
        // mov ecx, eax
        rt.asm.mov(ecx, eax).unwrap();
        // shr ecx, 0x10
        rt.asm.shr(ecx, 0x10).unwrap();
        // and ecx, 0xFF
        rt.asm.and(ecx, 0xFFu32).unwrap();

        // mov rax, [r14 + 0xE0] -> DWORD64 CONTEXT->R13
        rt.asm.mov(rax, ptr(r14 + 0xE0)).unwrap();
        // add rax, rcx
        rt.asm.add(rax, rcx).unwrap();
        // mov [r14 + 0xE0], rax -> DWORD64 CONTEXT->R13
        rt.asm.mov(ptr(r14 + 0xE0), rax).unwrap();

        // add [r14 + 0xF8], 0x7 -> CONTEXT->Rip
        rt.asm.add(qword_ptr(r14 + 0xF8), 0x7).unwrap();

        // mov rax, -0x1 -> EXCEPTION_CONTINUE_EXECUTION
        rt.asm.mov(rax, -0x1i64 as u64).unwrap();
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut continue_search).unwrap();
    {
        // mov rax, 0x0 -> EXCEPTION_CONTINUE_SEARCH
        rt.asm.mov(rax, 0x0u64).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // add rsp, 0x28
        rt.asm.add(rsp, 0x28).unwrap();
        // pop r14
        rt.asm.pop(r14).unwrap();
        // pop r13
        rt.asm.pop(r13).unwrap();
        // pop r12
        rt.asm.pop(r12).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\tests\Cargo.toml =====

[package]
name = "tests"
version = "0.1.0"
edition = "2021"

[dependencies]
iced-x86 = { version = "1.21.0", features = ["code_asm"] }
windows = { version = "0.62.2", features = ["Win32_System_Memory"] }
runtime = { path = "../runtime" }

// ===== FILE: C:\Users\Radon\Desktop\dev\binsafe\tests\src\lib.rs =====

#[cfg(test)]
mod tests {
    use std::{ffi::c_void, mem, ptr};

    use iced_x86::{
        code_asm::{ptr, rcx, rdx},
        Code, Instruction, MemoryOperand, Register,
    };
    use runtime::{
        mapper::Mappable,
        runtime::{DataDef, FnDef, Runtime},
        vm::{
            bytecode::{self, VMFlag, VMReg},
            stack,
        },
    };
    use windows::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    };

    struct Executor {
        rt: Runtime,
        mem: *mut c_void,
    }

    impl Executor {
        pub const TEST_KEY_SEED: u64 = 0x1234567890ABCDEF;
        pub const TEST_KEY_MUL: u64 = 0xFEDCBA0987654321;
        pub const TEST_KEY_ADD: u64 = 0x0123456789ABCDEF;

        pub const SIZE: usize = 0x3000;

        fn new() -> Self {
            let mut rt = Runtime::new(64);

            rt.define_data_qword(DataDef::VmKeySeed, Self::TEST_KEY_SEED);
            rt.define_data_qword(DataDef::VmKeyMul, Self::TEST_KEY_MUL);
            rt.define_data_qword(DataDef::VmKeyAdd, Self::TEST_KEY_ADD);

            let mem = unsafe {
                VirtualAlloc(
                    None,
                    Self::SIZE,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )
            };

            Self { rt, mem }
        }

        fn run(&mut self, registers: &mut [u64], bytecode: &[u8]) {
            let dispatch = self.rt.func_labels[&FnDef::VmDispatch];

            // call ...
            self.rt
                .asm
                .call(self.rt.func_labels[&FnDef::VmStackInitialize])
                .unwrap();

            // mov rcx, ...
            self.rt.asm.mov(rcx, registers.as_mut_ptr() as u64).unwrap();
            // lea rdx, [...]
            self.rt
                .asm
                .lea(rdx, ptr(self.rt.data_labels[&DataDef::VmCode]))
                .unwrap();
            // call ...
            stack::call(&mut self.rt, dispatch);
            // ret
            self.rt.asm.ret().unwrap();

            self.rt.define_data_bytes(DataDef::VmCode, bytecode);

            let ip = self.mem as u64;

            let code = self.rt.assemble(ip);

            assert!(code.len() <= Self::SIZE);

            unsafe {
                ptr::copy_nonoverlapping(code.as_ptr(), self.mem as *mut u8, code.len());

                let entry_point: extern "C" fn() = mem::transmute(self.mem);

                entry_point();
            }
        }
    }

    impl Drop for Executor {
        fn drop(&mut self) {
            unsafe {
                let _ = VirtualFree(self.mem, 0, MEM_RELEASE);
            }
        }
    }

    fn template(
        instructions: &[Instruction],
        setup: &[(VMReg, u64)],
        target: VMReg,
        expected: u64,
    ) {
        let mut executor = Executor::new();

        let mut registers = [0u64; VMReg::COUNT];

        for (reg, val) in setup {
            registers[(executor.rt.mapper.index(*reg)) as usize] = *val;
        }

        let mut vblock = bytecode::convert(&mut executor.rt.mapper, &instructions).unwrap();

        let mut key = Executor::TEST_KEY_SEED;

        for byte in &mut vblock {
            *byte ^= key as u8;
            key ^= *byte as u64;
            key = key
                .wrapping_mul(Executor::TEST_KEY_MUL)
                .wrapping_add(Executor::TEST_KEY_ADD);
        }

        let length = TryInto::<u16>::try_into(vblock.len()).unwrap();
        vblock.splice(0..0, length.to_le_bytes());

        executor.run(&mut registers, &vblock);

        assert_eq!(
            registers[(executor.rt.mapper.index(target)) as usize],
            expected,
            "Failed: {:?} | Expected: 0x{:X}, Got: 0x{:X}",
            instructions[0],
            expected,
            registers[(executor.rt.mapper.index(target)) as usize]
        );
    }

    fn flag(f: VMFlag) -> u64 {
        1 << (f as u64)
    }

    #[test]
    fn test_mov_reg_imm() {
        template(
            &[Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0x0000_0000).unwrap()],
            &[(VMReg::Rax, 0xFFFF_FFFF_FFFF_FFFF)],
            VMReg::Rax,
            0x0000_0000_0000_0000,
        );
    }

    #[test]
    fn test_flags() {
        // SF & PF
        template(
            &[Instruction::with2(Code::Add_rm64_imm8, Register::RAX, -0x1).unwrap()],
            &[(VMReg::Rax, 0x0)],
            VMReg::Flags,
            flag(VMFlag::Sign) | flag(VMFlag::Parity),
        );
        // OF & SF & AF & PF
        template(
            &[Instruction::with2(Code::Add_rm64_imm8, Register::RAX, 0x1).unwrap()],
            &[(VMReg::Rax, 0x7FFF_FFFF_FFFF_FFFF)],
            VMReg::Flags,
            flag(VMFlag::Overflow)
                | flag(VMFlag::Sign)
                | flag(VMFlag::Auxiliary)
                | flag(VMFlag::Parity),
        );
        // ZF & CF & AF & PF
        template(
            &[Instruction::with2(Code::Add_rm64_imm8, Register::RAX, 0x1).unwrap()],
            &[(VMReg::Rax, 0xFFFF_FFFF_FFFF_FFFF)],
            VMReg::Flags,
            flag(VMFlag::Carry)
                | flag(VMFlag::Parity)
                | flag(VMFlag::Auxiliary)
                | flag(VMFlag::Zero),
        );
    }

    #[test]
    fn test_jcc() {
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm8, Register::RAX, 0x1).unwrap(),
                Instruction::with_branch(Code::Je_rel8_64, 0xDEAD).unwrap(),
            ],
            &[(VMReg::Rax, 0x1)],
            VMReg::Vra,
            0xDEAD,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm8, Register::RAX, 0x2).unwrap(),
                Instruction::with_branch(Code::Jne_rel8_64, 0xDEAD).unwrap(),
            ],
            &[(VMReg::Rax, 0x1)],
            VMReg::Vra,
            0xDEAD,
        );
    }

    #[test]
    fn test_memory_load_store() {
        let mut buffer = [0u64; 2];

        let memory = buffer.as_mut_ptr() as u64;

        template(
            &[
                Instruction::with2(
                    Code::Mov_rm64_r64,
                    MemoryOperand::with_base_index_scale_displ_size(
                        Register::RBX,
                        Register::None,
                        1,
                        0,
                        8,
                    ),
                    Register::RAX,
                )
                .unwrap(),
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RCX,
                    MemoryOperand::with_base_index_scale_displ_size(
                        Register::RBX,
                        Register::None,
                        1,
                        0,
                        8,
                    ),
                )
                .unwrap(),
            ],
            &[(VMReg::Rax, 0xDEADC0DE), (VMReg::Rbx, memory)],
            VMReg::Rcx,
            0xDEADC0DE,
        );
    }

    #[test]
    fn test_push_pop() {
        let mut stack = [0u64; 2];

        let sp = unsafe { stack.as_mut_ptr().add(stack.len()) } as u64;

        template(
            &[
                Instruction::with1(Code::Push_r64, Register::RAX).unwrap(),
                Instruction::with1(Code::Push_r64, Register::RBX).unwrap(),
                Instruction::with1(Code::Pop_r64, Register::RBX).unwrap(),
                Instruction::with1(Code::Pop_r64, Register::RAX).unwrap(),
            ],
            &[(VMReg::Rsp, sp), (VMReg::Rax, 0x1111), (VMReg::Rbx, 0x2222)],
            VMReg::Rax,
            0x1111,
        );
    }

    #[test]
    fn test_lea_sib() {
        template(
            &[Instruction::with2(
                Code::Lea_r64_m,
                Register::RAX,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::RBX,
                    Register::RCX,
                    4,
                    0x8,
                    8,
                ),
            )
            .unwrap()],
            &[(VMReg::Rbx, 0x1000), (VMReg::Rcx, 0x10)],
            VMReg::Rax,
            0x1000 + (0x10 * 4) + 0x8,
        );
    }
}
