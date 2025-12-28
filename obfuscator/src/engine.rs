use exe::{Arch, Buffer, ImageSectionHeader, Offset, SectionCharacteristics, VecPE, PE, RVA};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter};
use logger::info;
use rand::Rng;
use runtime::runtime::Runtime;
use std::{collections::HashSet, fmt, mem, path::Path};

use crate::protections::Protection;

pub struct Block {
    pub ip: u64,
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

        let mut decoder = Decoder::with_ip(self.bitness, bytes, block.ip, DecoderOptions::NONE);

        block.instructions.clear();

        while decoder.can_decode() {
            let mut instr = Instruction::default();
            decoder.decode_out(&mut instr);
            if instr.is_invalid() {
                break;
            }
            block.instructions.push(instr);
        }
    }

    pub fn scan(&mut self) {
        let entry_point = self.pe.get_entrypoint().unwrap();

        let section = self.pe.get_section_by_rva(entry_point).unwrap();

        info!(
            "Protecting section '{}' at 0x{:08X}",
            Self::get_section_name(section),
            section.virtual_address.0
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
            });
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
