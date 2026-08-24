use exe::{
    Arch, Buffer, CCharString, ExportDirectory, ImageDirectoryEntry, ImageSectionHeader, Offset,
    PETranslation, RelocationDirectory, RelocationValue, SectionCharacteristics, ThunkData,
    ThunkFunctions, VecPE, HDR32_MAGIC, HDR64_MAGIC, PE, RVA,
};
use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter};
use logger::info;
use markers::{MARKER_BEGIN, MARKER_END, MARKER_SIZE};
use runtime::runtime::Runtime;
use std::{collections::HashSet, fmt, mem};

use crate::{args::Args, exceptions, protections::Protection};

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

pub struct Engine<'a> {
    pub pe: VecPE,
    pub bitness: u32,

    pub args: &'a Args,

    pub blocks: Vec<Block>,

    pub rt: Runtime,

    protections: Vec<Box<dyn Protection>>,
}

impl<'a> Engine<'a> {
    pub fn new(args: &'a Args) -> Self {
        let pe = VecPE::from_disk_file(&args.input).unwrap();

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
            args,
            blocks: Vec::new(),
            rt: Runtime::new(bitness),
            protections: Vec::new(),
        }
    }

    pub fn apply<T: Protection + Default + 'static>(&mut self) {
        self.protections.push(Box::<T>::default());
    }

    pub fn junk(&mut self, offset: usize, size: usize) {
        let bytes = (0..size).map(|_| rand::random()).collect::<Vec<u8>>();
        self.pe.write(offset, &bytes).unwrap();
    }

    pub fn nop(&mut self, offset: usize, size: usize) {
        self.pe.write(offset, &vec![0x90; size]).unwrap();
    }

    pub fn replace(&mut self, index: usize, data: &[u8]) {
        let (offset, size, rva) = {
            let block = &self.blocks[index];
            assert!(data.len() <= block.size);
            (block.offset, block.size, block.rva)
        };

        self.pe.write(offset, data).unwrap();

        self.junk(offset + data.len(), size - data.len());

        let bytes = self.pe.get_slice_ref::<u8>(offset, data.len()).unwrap();

        let mut decoder = Decoder::with_ip(self.bitness, bytes, rva as u64, DecoderOptions::NONE);

        let block = &mut self.blocks[index];
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
        let entry_point = self.pe.get_entrypoint().unwrap();
        let code_section = self.pe.get_section_by_rva(entry_point).unwrap();

        info!(
            "Section VA: 0x{:X}, file offset: 0x{:X}",
            code_section.virtual_address.0, code_section.pointer_to_raw_data.0
        );
        info!(
            "Protecting section '{}' at 0x{:08X}",
            Self::get_section_name(&code_section),
            code_section.virtual_address.0
        );

        let ip = code_section.virtual_address.0 as u64;
        let code = code_section.read(&self.pe).unwrap().to_vec();

        if self.scan_markers(ip, &code) {
            return;
        }

        self.scan_blocks(ip, &code, &code_section);
    }

    fn scan_markers(&mut self, ip: u64, code: &[u8]) -> bool {
        let mut markers = Vec::new();
        let mut begin = None;
        let mut cursor = 0;

        while cursor + MARKER_SIZE <= code.len() {
            if code[cursor..cursor + MARKER_SIZE] == MARKER_BEGIN {
                begin = Some(cursor + MARKER_SIZE);
                cursor += MARKER_SIZE;
                continue;
            }
            if code[cursor..cursor + MARKER_SIZE] == MARKER_END {
                if let Some(start) = begin.take() {
                    markers.push((start, cursor));
                }
                cursor += MARKER_SIZE;
                continue;
            }
            cursor += 1;
        }

        if markers.is_empty() {
            return false;
        }

        info!("Found {} marked regions", markers.len());

        let mut capture = |block: &mut Vec<Instruction>, end: u32| {
            if block.is_empty() {
                return;
            }
            let rva = block[0].ip() as u32;
            let offset = self.pe.translate(PETranslation::Memory(RVA(rva))).unwrap();
            let size = (end - rva) as usize;
            let block = Block {
                rva,
                offset,
                size,
                instructions: mem::take(block),
            };
            info!("{block}");
            self.blocks.push(block);
        };

        for &(start, end) in &markers {
            let rva = ip as u32 + start as u32;
            let mut decoder = Decoder::with_ip(
                self.bitness,
                &code[start..end],
                rva as u64,
                DecoderOptions::NONE,
            );

            let mut instruction = Instruction::default();
            let mut block = Vec::new();

            while decoder.can_decode() {
                decoder.decode_out(&mut instruction);

                if instruction.is_invalid() {
                    if !block.is_empty() {
                        capture(&mut block, instruction.ip() as u32);
                    }
                    break;
                }

                block.push(instruction);

                if !matches!(instruction.flow_control(), FlowControl::Next) {
                    capture(&mut block, instruction.next_ip() as u32);
                }
            }

            if !block.is_empty() {
                capture(&mut block, ip as u32 + end as u32);
            }
        }

        for (start, end) in markers {
            let start = self
                .pe
                .translate(PETranslation::Memory(RVA(ip as u32 + start as u32)))
                .unwrap();
            let end = self
                .pe
                .translate(PETranslation::Memory(RVA(ip as u32 + end as u32)))
                .unwrap();

            self.nop(start - MARKER_SIZE, MARKER_SIZE);
            self.nop(end, MARKER_SIZE);
        }

        info!("Found {} blocks", self.blocks.len());

        true
    }

    fn scan_blocks(&mut self, ip: u64, code: &[u8], code_section: &ImageSectionHeader) {
        let data_references = self.collect_data_references(code, ip);

        let mut code_references = self
            .collect_code_references(code, ip, code_section, &data_references)
            .into_iter()
            .collect::<Vec<u32>>();
        code_references.sort();

        let mut capture = |block: &mut Vec<Instruction>, end: u32| {
            if block.is_empty() {
                return;
            }
            let rva = block[0].ip() as u32;
            let offset = self.pe.translate(PETranslation::Memory(RVA(rva))).unwrap();
            let size = (end - rva) as usize;
            self.blocks.push(Block {
                rva,
                offset,
                size,
                instructions: mem::take(block),
            });
        };

        let mut decoder = Decoder::with_ip(self.bitness, code, ip, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        let mut block = Vec::new();
        let mut inblock = false;

        while decoder.can_decode() {
            let rva = decoder.ip() as u32;

            if code_references.binary_search(&rva).is_ok() {
                if inblock {
                    capture(&mut block, rva);
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
            let position = code_references.binary_search(&end).unwrap_or_else(|e| e);
            let overlaps = position > 0
                && code_references[position - 1] > start
                && code_references[position - 1] < end;

            if overlaps {
                capture(&mut block, start);
                inblock = false;
                continue;
            }

            block.push(instruction);

            if !matches!(instruction.flow_control(), FlowControl::Next) {
                capture(&mut block, instruction.next_ip() as u32);
                inblock = false;
            }
        }

        info!("Found {} blocks", self.blocks.len());

        // let start = 1230;
        // let end = 1335;
        // let middle = start + (end - start) / 2;

        // self.blocks.drain(end..);
        // self.blocks.drain(..start);

        // debug!("{} to {} (middle: {})", start, end, middle);

        // debug!(
        //     "0x{:016X} {}",
        //     self.pe.get_image_base().unwrap() + self.blocks[0].rva as u64,
        //     self.blocks[0]
        // );
    }

    fn collect_data_references(&self, code: &[u8], ip: u64) -> HashSet<u32> {
        let mut data_references = HashSet::new();
        let mut decoder = Decoder::with_ip(self.bitness, code, ip, DecoderOptions::NONE);
        let mut instruction = Instruction::default();

        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);

            if instruction.is_invalid() {
                continue;
            }

            if instruction.is_ip_rel_memory_operand() {
                data_references.insert(instruction.ip_rel_memory_address() as u32);
            }
        }

        data_references
    }

    fn collect_static_references(&self, code_section: &ImageSectionHeader) -> HashSet<u32> {
        let image_base = self.pe.get_image_base().unwrap();
        let entry_point = self.pe.get_entrypoint().unwrap();

        let mut references = HashSet::new();
        references.insert(entry_point.0);

        for handler in exceptions::get_exception_handlers(&self.pe) {
            if code_section.has_rva(RVA(handler)) {
                references.insert(handler);
            }
        }

        if let Ok(exports) = ExportDirectory::parse(&self.pe) {
            if let Ok(directory) = self.pe.get_data_directory(ImageDirectoryEntry::Export) {
                let start = directory.virtual_address;
                let end = RVA(start.0 + directory.size);

                if let Ok(functions) = exports.get_functions(&self.pe) {
                    for function in functions {
                        if let ThunkData::Function(rva) = function.parse_export(start, end) {
                            if code_section.has_rva(rva) {
                                references.insert(rva.0);
                            }
                        }
                    }
                }
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
                        references.insert(target_rva);
                    }
                }
            }
        }

        references
    }

    fn collect_code_references(
        &self,
        code: &[u8],
        ip: u64,
        code_section: &ImageSectionHeader,
        data_references: &HashSet<u32>,
    ) -> HashSet<u32> {
        let mut references = self.collect_static_references(code_section);
        let mut decoder = Decoder::with_ip(self.bitness, code, ip, DecoderOptions::NONE);
        let mut instruction = Instruction::default();
        let mut previous = Vec::new();

        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);
            if instruction.is_invalid() {
                previous.clear();
                continue;
            }

            match instruction.flow_control() {
                FlowControl::ConditionalBranch
                | FlowControl::UnconditionalBranch
                | FlowControl::Call => {
                    let target = instruction.near_branch_target() as u32;
                    if code_section.has_rva(RVA(target)) {
                        references.insert(target);
                    }
                }
                _ => {}
            }

            if matches!(
                instruction.flow_control(),
                FlowControl::ConditionalBranch | FlowControl::Call | FlowControl::IndirectCall
            ) {
                references.insert(instruction.next_ip() as u32);
            }

            let flow = instruction.flow_control();
            previous.push(instruction);

            if !matches!(
                flow,
                FlowControl::IndirectBranch
                    | FlowControl::UnconditionalBranch
                    | FlowControl::Return
            ) {
                continue;
            }

            if flow == FlowControl::IndirectBranch {
                let targets = self.collect_switch_table(&previous, data_references);

                for target in targets {
                    references.insert(target);
                }
            }

            previous.clear();
        }

        references
    }

    fn collect_switch_table(
        &self,
        block: &[Instruction],
        data_references: &HashSet<u32>,
    ) -> Vec<u32> {
        use iced_x86::{OpKind, Register};

        let indirect = block.last().unwrap();
        if indirect.op0_kind() != OpKind::Register {
            return Vec::new();
        }

        let source_section = self
            .pe
            .get_section_by_rva(RVA(indirect.ip() as u32))
            .unwrap();

        let mut registers = Vec::new();
        registers.push(indirect.op0_register());

        for instruction in block.iter().rev() {
            for register in registers.clone() {
                if instruction.op0_register() != register {
                    continue;
                }

                for i in 1..instruction.op_count() {
                    if instruction.op_kind(i) == OpKind::Register {
                        let source = instruction.op_register(i);
                        if !registers.contains(&source) {
                            registers.push(source);
                        }
                    }

                    if instruction.memory_base() != Register::RIP {
                        continue;
                    }
                    if instruction.op_kind(i) != OpKind::Memory {
                        continue;
                    }

                    let table_rva = instruction.ip_rel_memory_address() as u32;
                    let destination_section = match self.pe.get_section_by_rva(RVA(table_rva)) {
                        Ok(s) => s,
                        Err(_) => continue,
                    };
                    let destination_data = match destination_section.read(&self.pe) {
                        Ok(d) => d,
                        Err(_) => continue,
                    };

                    let offset = (table_rva - destination_section.virtual_address.0) as usize;
                    let mut targets = Vec::new();
                    let mut cursor = offset;

                    while cursor + size_of::<i32>() <= destination_data.len() {
                        let current_rva = table_rva + (cursor - offset) as u32;
                        if current_rva != table_rva && data_references.contains(&current_rva) {
                            break;
                        }

                        let displacement = i32::from_le_bytes(
                            destination_data[cursor..cursor + size_of::<i32>()]
                                .try_into()
                                .unwrap(),
                        );
                        let target_rva = (table_rva as i32 + displacement as i32) as u32;

                        if target_rva < indirect.ip() as u32 {
                            cursor += size_of::<i32>();
                            continue;
                        }
                        if !source_section.has_rva(RVA(target_rva)) {
                            break;
                        }

                        targets.push(target_rva);
                        cursor += size_of::<i32>();
                    }

                    if !targets.is_empty() {
                        return targets;
                    }
                }
            }
        }

        Vec::new()
    }

    pub fn get_end_of_sections(&self) -> u32 {
        let sections = self.pe.get_section_table().unwrap();
        let end_section = sections[sections.len() - 1];
        self.pe
            .align_to_section(RVA(end_section.virtual_address.0 + end_section.virtual_size))
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

        let mut section = ImageSectionHeader::default();
        section.set_name(name);
        section.virtual_size = virtual_size;
        section.size_of_raw_data = raw_size;
        section.characteristics = characteristics;

        let magic = self.pe.get_nt_magic().unwrap();

        let (pointer_to_symbol_table, number_of_symbols) = if magic == HDR32_MAGIC {
            let h32 = self.pe.get_nt_headers_32().unwrap();
            (
                h32.file_header.pointer_to_symbol_table.0,
                h32.file_header.number_of_symbols,
            )
        } else {
            let h64 = self.pe.get_nt_headers_64().unwrap();
            (
                h64.file_header.pointer_to_symbol_table.0,
                h64.file_header.number_of_symbols,
            )
        };

        let symbol_table = if pointer_to_symbol_table != 0 && number_of_symbols != 0 {
            let symbol_table = self
                .pe
                .get_slice_ref::<u8>(
                    pointer_to_symbol_table as usize,
                    self.pe.len() - pointer_to_symbol_table as usize,
                )
                .unwrap()
                .to_vec();
            self.pe.truncate(pointer_to_symbol_table as usize);
            Some(symbol_table)
        } else {
            None
        };

        let section = self.pe.append_section(&section).unwrap();
        self.pe.append(content);
        self.pe.pad_to_alignment().unwrap();

        if let Some(symbol_table) = symbol_table {
            let pointer_to_symbol_table = self.pe.len() as u32;

            self.pe.append(&symbol_table);

            if magic == HDR32_MAGIC {
                let h32 = self.pe.get_mut_nt_headers_32_ref().unwrap();
                h32.file_header.pointer_to_symbol_table = Offset(pointer_to_symbol_table);
            } else if magic == HDR64_MAGIC {
                let h64 = self.pe.get_mut_nt_headers_64_ref().unwrap();
                h64.file_header.pointer_to_symbol_table = Offset(pointer_to_symbol_table);
            }
        }

        let size_of_image = self.pe.calculate_memory_size().unwrap() as u32;

        if magic == HDR32_MAGIC {
            let h32 = self.pe.get_mut_nt_headers_32_ref().unwrap();
            h32.optional_header.size_of_image = size_of_image;
        } else if magic == HDR64_MAGIC {
            let h64 = self.pe.get_mut_nt_headers_64_ref().unwrap();
            h64.optional_header.size_of_image = size_of_image;
        }

        section
    }

    pub fn execute(&mut self) -> Vec<u8> {
        let mut protections = mem::take(&mut self.protections);

        for protection in &mut protections {
            protection.initialize(self);
        }

        let ip = self.get_end_of_sections() as u64;
        let code = self.rt.assemble(ip);
        let new_section = self.create_section(
            Some("💀"),
            &code,
            SectionCharacteristics::CNT_CODE
                | SectionCharacteristics::CNT_INITIALIZED_DATA
                | SectionCharacteristics::MEM_EXECUTE
                | SectionCharacteristics::MEM_READ
                | SectionCharacteristics::MEM_WRITE,
        );

        info!(
            "Created new section '{}' at 0x{:08X}",
            new_section.name.as_str().unwrap(),
            new_section.virtual_address.0
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
