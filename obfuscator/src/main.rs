use exe::{
    Address, Arch, Buffer, ImageSectionHeader, NTHeaders, NTHeadersMut, Offset, PETranslation,
    SectionCharacteristics, TLSDirectory, VecPE, PE, RVA, VA, VA32, VA64,
};
use iced_x86::{code_asm::CodeAssembler, Decoder, DecoderOptions, Instruction};
use rand::Rng;
use runtime::{
    runtime::{DataDef, Runtime},
    vm::bytecode::{self, VMBytecode},
};
use std::{
    env,
    fs::{self},
    path::Path,
};

pub struct Engine {
    pe: VecPE,
    bitness: u32,
    bytecode: VMBytecode,
}

impl Engine {
    pub fn new(filename: &Path) -> Self {
        let pe = VecPE::from_disk_file(&filename).unwrap();

        let bitness = match pe.get_arch().unwrap() {
            Arch::X64 => 64,
            _ => panic!("only 64-bit binaries are supported"),
        };

        Self {
            pe,
            bitness,
            bytecode: VMBytecode::default(),
        }
    }

    pub fn protect(&mut self) {
        let entry_point = self.pe.get_entrypoint().unwrap();
        let section = self.pe.get_section_by_rva(entry_point).unwrap();

        let ip = section.virtual_address.0 as u64;
        let mut code = section.read(&self.pe).unwrap().to_vec();

        let mut decoder = Decoder::with_ip(64, &code, ip, DecoderOptions::NONE);

        let mut instructions = Vec::new();

        let mut instruction = Instruction::default();

        while decoder.can_decode() {
            decoder.decode_out(&mut instruction);

            if instruction.is_invalid() {
                break;
            }

            instructions.push(instruction);
        }

        for instruction in instructions {
            let bytes = match bytecode::convert(&instruction) {
                Some(bytes) => bytes,
                None => continue,
            };

            let offset = (instruction.ip() - ip) as usize;

            code[offset] = 0xCC;

            for j in 1..instruction.len() {
                code[offset + j] = rand::thread_rng().gen();
            }

            let ip = instruction.ip() as u32;
            self.bytecode.set(ip, bytes);
        }

        let offset = section.data_offset(self.pe.get_type());
        self.pe.write(offset, code).unwrap();
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

    fn get_entry_point(&self) -> u32 {
        match self.pe.get_valid_nt_headers().unwrap() {
            NTHeaders::NTHeaders32(h32) => h32.optional_header.address_of_entry_point.0,
            NTHeaders::NTHeaders64(h64) => h64.optional_header.address_of_entry_point.0,
        }
    }

    fn set_entry_point(&mut self, entry_point: u32) {
        match self.pe.get_valid_mut_nt_headers().unwrap() {
            NTHeadersMut::NTHeaders32(h32) => {
                h32.optional_header.address_of_entry_point = RVA(entry_point)
            }
            NTHeadersMut::NTHeaders64(h64) => {
                h64.optional_header.address_of_entry_point = RVA(entry_point)
            }
        }
    }

    fn rva_to_va(&self, rva: RVA) -> VA {
        let image_base = self.pe.get_image_base().unwrap();

        match self.pe.get_arch().unwrap() {
            Arch::X86 => VA::VA32(VA32(rva.0 + (image_base as u32))),
            Arch::X64 => VA::VA64(VA64((rva.0 as u64) + image_base)),
        }
    }

    fn create_section(&mut self, content: &[u8], characteristics: SectionCharacteristics) {
        let size = content.len() as u32;

        let virtual_size = self.pe.align_to_section(RVA(size)).unwrap().0;
        let raw_size = self.pe.align_to_file(Offset(size)).unwrap().0;

        let section = self
            .pe
            .append_section(&ImageSectionHeader::default())
            .unwrap();
        section.virtual_size = virtual_size;
        section.size_of_raw_data = raw_size;
        section.characteristics = characteristics;

        self.pe.append(content);
        self.pe.pad_to_alignment().unwrap();

        self.pe.fix_image_size().unwrap();
    }

    fn create_entry_point(&mut self, rtfasm: &mut Runtime, new_entry_point: u32) {
        let tls = TLSDirectory::parse(&self.pe).unwrap();

        macro_rules! get_callbacks {
            ($tls:expr, $va_type:path) => {
                $tls.get_callbacks(&self.pe)
                    .unwrap()
                    .iter()
                    .map(|va| self.pe.va_to_rva($va_type(*va)).unwrap().0)
                    .collect::<Vec<u32>>()
            };
        }

        let old_callbacks = match tls {
            TLSDirectory::TLS32(tls32) => get_callbacks!(tls32, VA::VA32),
            TLSDirectory::TLS64(tls64) => get_callbacks!(tls64, VA::VA64),
        };

        if old_callbacks.is_empty() {
            let oep = self.get_entry_point();
            rtfasm.build_entry_point(oep);
            self.set_entry_point(new_entry_point);
            return;
        }

        rtfasm.build_callbacks(&old_callbacks);

        let new_callback = self.rva_to_va(RVA(new_entry_point));

        macro_rules! redirect_callbacks {
            ($tls:expr, $va_type:ty, $redirect:expr) => {
                let rva = $tls.address_of_callbacks.as_rva(&self.pe).unwrap();
                let size = $tls.get_callback_size(&self.pe).unwrap();
                let offset = self.pe.translate(PETranslation::Memory(rva)).unwrap();
                let callbacks = self.pe.get_mut_slice_ref::<$va_type>(offset, size).unwrap();

                for (i, cb) in callbacks.iter_mut().enumerate() {
                    cb.0 = if i == 0 { $redirect } else { 0 };
                }
            };
        }

        match (tls, new_callback) {
            (TLSDirectory::TLS32(tls32), VA::VA32(va32)) => {
                redirect_callbacks!(tls32, VA32, va32.0);
            }
            (TLSDirectory::TLS64(tls64), VA::VA64(va64)) => {
                redirect_callbacks!(tls64, VA64, va64.0);
            }
            _ => unreachable!(),
        }
    }

    pub fn rebuild(&mut self) -> Vec<u8> {
        let new_entry_point = self.get_start_of_next_section();

        let mut assembler = CodeAssembler::new(self.bitness).unwrap();
        let mut rtfasm = Runtime::new(&mut assembler);

        self.create_entry_point(&mut rtfasm, new_entry_point);

        rtfasm.define_data(DataDef::BYTECODE, &self.bytecode.encode());

        let code = rtfasm.assemble(new_entry_point as u64);
        self.create_section(
            &code,
            SectionCharacteristics::CNT_CODE
                | SectionCharacteristics::MEM_EXECUTE
                | SectionCharacteristics::MEM_READ
                | SectionCharacteristics::MEM_WRITE,
        );

        self.pe.to_vec()
    }
}

fn main() {
    let args = env::args().collect::<Vec<String>>();

    let input = Path::new(&args[1]);

    let mut engine = Engine::new(input);
    engine.protect();
    let image = engine.rebuild();

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

    fs::write(output, image).unwrap();
}
