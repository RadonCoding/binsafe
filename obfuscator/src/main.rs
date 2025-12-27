use exe::{Arch, Buffer, ImageSectionHeader, VecPE, PE, RVA};
use iced_x86::{
    Code, Decoder, DecoderOptions, Encoder, FlowControl, Formatter, Instruction, IntelFormatter,
};
use logger::info;
use rand::Rng;
use std::{
    env,
    fs::{self},
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
    bitness: u32,
    blocks: Vec<Block>,
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
        }
    }

    pub fn scan(&mut self) {
        let entry_point = self.pe.get_entrypoint().unwrap();

        let section = self.pe.get_section_by_rva(entry_point).unwrap();

        info!(
            "Protecting section '{}' at 0x{:016X}",
            Self::get_section_name(section),
            self.as_absolute(section.virtual_address.0)
        );

        let ip = section.virtual_address.0 as u64;
        let code = section.read(&self.pe).unwrap();

        let mut decoder = Decoder::with_ip(self.bitness, &code, ip, DecoderOptions::NONE);

        let mut block = Vec::new();

        let mut instruction = Instruction::default();

        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);

            if instruction.is_invalid() {
                break;
            }

            block.push(instruction);

            if instruction.flow_control() == FlowControl::Next {
                continue;
            }

            if block.len() > 1 {
                let ip = block[0].ip();
                let offset = self
                    .pe
                    .translate(exe::PETranslation::Memory(RVA(ip as u32)))
                    .unwrap();
                let size = (block[block.len() - 1].next_ip() - ip) as usize;

                self.blocks.push(Block {
                    ip,
                    offset,
                    size,
                    instructions: block.clone(),
                    virtualized: false,
                });
            }

            block.clear();
        }

        let mut formatter = IntelFormatter::new();
        let mut output = String::new();

        const HEXBYTES_COLUMN_BYTE_LENGTH: usize = 10;

        for block in &self.blocks {
            println!(
                "Block [offset: 0x{:X}, size: {} bytes]",
                block.offset, block.size
            );

            for instruction in &block.instructions {
                output.clear();

                formatter.format(&instruction, &mut output);

                let rva = instruction.ip() as u32;

                print!("{:016X} ", self.as_absolute(rva));

                let offset = (instruction.ip() - ip) as usize;
                let bytes = &code[offset..offset + instruction.len()];

                for b in bytes.iter() {
                    print!("{:02X}", b);
                }
                if bytes.len() < HEXBYTES_COLUMN_BYTE_LENGTH {
                    for _ in 0..HEXBYTES_COLUMN_BYTE_LENGTH - bytes.len() {
                        print!("  ");
                    }
                }
                println!(" {}", output);
            }

            println!();
        }

        info!("Found {} blocks", self.blocks.len());
    }

    fn as_absolute(&self, address: u32) -> u64 {
        self.pe.get_image_base().unwrap() + address as u64
    }

    fn get_section_name(section: &ImageSectionHeader) -> String {
        let bytes = section.name.iter().map(|c| c.0).collect::<Vec<u8>>();
        String::from_utf8_lossy(&bytes)
            .trim_end_matches('\0')
            .to_string()
    }

    pub fn virtualize(&mut self) {
        // TODO: Create VM entry-point
        let entry_point = 0x1000u64;

        for block in &mut self.blocks {
            let instruction = Instruction::with_branch(Code::Call_rel32_64, entry_point).unwrap();

            let mut encoder = Encoder::new(self.bitness);
            encoder.encode(&instruction, block.ip).unwrap();

            let dispatch = encoder.take_buffer();

            // Skip blocks that are too small
            if dispatch.len() > block.size {
                continue;
            }

            // TODO: Check that all instructions in the block can be virtualized

            self.pe.write(block.offset, &dispatch).unwrap();

            let remaining = block.size - dispatch.len();

            if remaining > 0 {
                let mut junk = vec![0u8; remaining];
                rand::thread_rng().fill(&mut junk[..]);

                self.pe.write(block.offset + dispatch.len(), &junk).unwrap();
            }

            block.virtualized = true;
        }
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
