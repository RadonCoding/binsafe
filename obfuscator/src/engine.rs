use exe::{
    Arch, Buffer, ImageSectionHeader, Offset, PETranslation, RelocationDirectory, RelocationValue,
    SectionCharacteristics, VecPE, PE, RVA,
};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter};
use logger::info;
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
            // let mut junk = vec![0u8; remaining];
            // rand::thread_rng().fill(&mut junk[..]);
            let junk = vec![0xCCu8; remaining];

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
                break;
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

        for &target in &sorted {
            if !self.blocks.iter().any(|b| b.rva == target) {
                panic!(
                    "Jump target 0x{:016X} was not covered by any block",
                    image_base + target as u64
                );
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
