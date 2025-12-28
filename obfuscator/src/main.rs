use exe::{Arch, Buffer, ImageSectionHeader, Offset, SectionCharacteristics, VecPE, PE, RVA};
use iced_x86::{
    code_asm::CodeAssembler, Decoder, DecoderOptions, FlowControl, Formatter, Instruction,
    IntelFormatter,
};
use logger::info;
use rand::Rng;
use runtime::{
    runtime::{DataDef, FnDef, Runtime},
    vm::bytecode::{self, VMOp},
};
use shared::constants::VM_DISPATCH_SIZE;
use std::{
    collections::{HashMap, HashSet},
    env,
    fs::{self},
    mem,
    path::Path,
};

pub struct Block {
    ip: u64,
    offset: usize,
    size: usize,
    instructions: Vec<Instruction>,
    virtualized: bool,
}

pub struct Engine {
    pe: VecPE,
    image_base: u64,
    bitness: u32,
    blocks: Vec<Block>,
    rt: Runtime,
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

        let image_base = pe.get_image_base().unwrap();

        Self {
            pe,
            image_base,
            bitness,
            blocks: Vec::new(),
            rt: Runtime::new(bitness),
        }
    }

    fn print_block(image_base: u64, block: &Block) {
        println!(
            "Block [offset: 0x{:X}, size: {} bytes, virtualized: {}]",
            block.offset, block.size, block.virtualized
        );

        let mut formatter = IntelFormatter::new();
        let mut output = String::new();

        for instruction in &block.instructions {
            output.clear();

            formatter.format(&instruction, &mut output);

            let rva = instruction.ip() as u32;

            print!("{:016X} ", image_base + rva as u64);

            println!(" {}", output);
        }

        println!();
    }

    pub fn scan(&mut self) {
        let entry_point = self.pe.get_entrypoint().unwrap();

        let section = self.pe.get_section_by_rva(entry_point).unwrap();

        info!(
            "Protecting section '{}' at 0x{:016X}",
            Self::get_section_name(section),
            self.image_base + section.virtual_address.0 as u64
        );

        let ip = section.virtual_address.0 as u64;
        let code = section.read(&self.pe).unwrap();

        let mut jumps = HashSet::new();

        let mut decoder = Decoder::with_ip(self.bitness, &code, ip, DecoderOptions::NONE);

        let mut instruction = Instruction::default();

        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);

            if instruction.is_invalid() {
                break;
            }

            match instruction.flow_control() {
                FlowControl::ConditionalBranch
                | FlowControl::UnconditionalBranch
                | FlowControl::Call => {
                    let target = instruction.near_branch_target();

                    if target >= ip && target < ip + code.len() as u64 {
                        jumps.insert(target);
                    }
                }
                _ => {}
            }
        }

        let mut decoder = Decoder::with_ip(self.bitness, &code, ip, DecoderOptions::NONE);
        let mut block = Vec::<Instruction>::new();

        while decoder.can_decode() {
            let current = decoder.ip();

            if jumps.contains(&current) && !block.is_empty() {
                let ip = block[0].ip();
                let offset = self
                    .pe
                    .translate(exe::PETranslation::Memory(RVA(ip as u32)))
                    .unwrap();
                let size = (current - ip) as usize;

                self.blocks.push(Block {
                    ip,
                    offset,
                    size,
                    instructions: mem::take(&mut block),
                    virtualized: false,
                });
            }

            decoder.decode_out(&mut instruction);

            if instruction.is_invalid() {
                break;
            }

            block.push(instruction);

            if instruction.flow_control() == FlowControl::Next {
                continue;
            }

            let ip = block[0].ip();
            let offset = self
                .pe
                .translate(exe::PETranslation::Memory(RVA(ip as u32)))
                .unwrap();
            let size = (instruction.next_ip() - ip) as usize;

            self.blocks.push(Block {
                ip,
                offset,
                size,
                instructions: mem::take(&mut block),
                virtualized: false,
            });
        }

        info!("Found {} blocks", self.blocks.len());
    }

    fn get_start_of_next_section(&self) -> u32 {
        let sections = self.pe.get_section_table().unwrap();
        let last_section = sections[sections.len() - 1];
        self.pe
            .align_to_section(RVA(
                last_section.virtual_address.0 + last_section.virtual_size
            ))
            .unwrap()
            .0
    }

    fn get_section_name(section: &ImageSectionHeader) -> String {
        let bytes = section.name.iter().map(|c| c.0).collect::<Vec<u8>>();
        String::from_utf8_lossy(&bytes)
            .trim_end_matches('\0')
            .to_string()
    }

    fn create_section(
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

    pub fn virtualize(&mut self) {
        let mut vblocks = HashMap::new();

        let mut vcode = Vec::new();

        'outer: for block in &mut self.blocks {
            // Skip blocks that are too small
            if block.size < VM_DISPATCH_SIZE {
                continue;
            }

            let mut vblock = Vec::new();

            let next_ip = block.instructions[block.instructions.len() - 1].next_ip() as u32;

            let address = next_ip as u64;

            for instruction in &block.instructions {
                let bytecode = match bytecode::convert(address, instruction) {
                    Some(virtualized) => virtualized,
                    None => continue 'outer,
                };
                vblock.extend(bytecode);
            }

            vblocks.insert(block.ip, vcode.len() as i32);

            vblock.splice(0..0, next_ip.to_le_bytes());

            vblock.push(VMOp::Invalid as u8);

            vcode.extend(vblock);
        }

        self.rt.define_data(DataDef::VmCode, &vcode);

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

        let vm_entry = self.rt.lookup(self.rt.func_labels[&FnDef::VmEntry]);

        for block in &mut self.blocks {
            if !vblocks.contains_key(&block.ip) {
                continue;
            }

            let vm_offset = vblocks[&block.ip];

            let mut asm = CodeAssembler::new(self.bitness).unwrap();
            asm.push(vm_offset).unwrap();
            asm.jmp(vm_entry).unwrap();

            let dispatch = asm.assemble(block.ip).unwrap();

            assert!(dispatch.len() <= VM_DISPATCH_SIZE);

            self.pe.write(block.offset, &dispatch).unwrap();

            let remaining = block.size - dispatch.len();

            if remaining > 0 {
                let mut junk = vec![0u8; remaining];
                rand::thread_rng().fill(&mut junk[..]);

                self.pe.write(block.offset + dispatch.len(), &junk).unwrap();
            }

            block.virtualized = true;
        }

        info!("Virtualized {} blocks", vblocks.len());
    }

    pub fn mutate(&mut self) {
        for block in &mut self.blocks {
            if block.virtualized {
                continue;
            }

            // TODO: Define mutation passes and execute based on mnemonic
        }
    }

    pub fn rebuild(&mut self) -> Vec<u8> {
        let output = self.pe.to_vec();

        for block in &self.blocks {
            Self::print_block(self.image_base, block);
        }

        info!(
            "Rebuilt {}-bit binary ({:.2} MB)",
            self.bitness,
            self.pe.len() as f64 / 1_000_000.0,
        );

        output
    }
}

fn main() {
    let args = env::args().collect::<Vec<String>>();

    let input = Path::new(&args[1]);

    let mut engine = Engine::new(input);
    engine.scan();
    engine.virtualize();
    engine.mutate();
    let protected = engine.rebuild();

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
