use exe::{
    Buffer, CCharString, ImageDOSHeader, ImageDirectoryEntry, ImageNTHeaders64,
    ImageOptionalHeader64, ImageSectionHeader, ImportData, ImportDirectory, RelocationDirectory,
    RelocationValue, SectionCharacteristics, VecPE, PE, RVA,
};
use logger::info;
use runtime::{
    runtime::{DataDef, FnDef, ImportDef},
    vm::{
        bytecode::{VMReg, VMSeg, VMWidth},
        encoders::{store_memory::StoreMemory, Encode},
    },
};

use crate::protections::virtualization::language::*;
use crate::protections::virtualization::{
    assemble_bytecode, create_attestation, create_bytecode, write_displacement,
};
use crate::protections::Protection;
use crate::{engine::Engine, exceptions::RuntimeFunction};

const SIZE_OF_HEADERS: usize = 0x400;

const MEM_COMMIT: u64 = 0x1000;
const MEM_RESERVE: u64 = 0x2000;

const PAGE_NOACCESS: u64 = 0x01;
const PAGE_READONLY: u64 = 0x02;
const PAGE_READWRITE: u64 = 0x04;
const PAGE_EXECUTE: u64 = 0x10;
const PAGE_EXECUTE_READ: u64 = 0x20;
const PAGE_EXECUTE_READWRITE: u64 = 0x40;

enum Symbol {
    Name(u32),
    Ordinal(u16),
}

struct Section {
    rva: u32,
    virtual_size: u32,
    offset: u32,
    size: u32,
    characteristics: SectionCharacteristics,
}

struct Import {
    slot: u32,
    module: u32,
    symbol: Symbol,
}

#[derive(Default)]
struct Image {
    size: u64,
    base: u64,
    entrypoint: u32,
    exceptions_rva: u32,
    exceptions_size: u32,
    subsystem: u16,
    header: Vec<u8>,
    blob: Vec<u8>,
    sections: Vec<Section>,
    relocations: Vec<u32>,
    names: Vec<u8>,
    imports: Vec<Import>,
}

fn generate_header(sections: &[Section]) -> Vec<u8> {
    let mut pe =
        VecPE::new_disk(SIZE_OF_HEADERS + sections.len() * size_of::<ImageSectionHeader>());

    pe.write_val(0, &ImageDOSHeader::default()).unwrap();

    let e_lfanew = pe.e_lfanew().unwrap();

    let mut headers = ImageNTHeaders64::default();
    headers.file_header.number_of_sections = sections.len() as u16;
    headers.file_header.size_of_optional_header = size_of::<ImageOptionalHeader64>() as u16;

    pe.write_val(e_lfanew.0 as usize, &headers).unwrap();

    let table = e_lfanew.0 as usize + size_of::<ImageNTHeaders64>();

    for (index, section) in sections.iter().enumerate() {
        let mut entry = ImageSectionHeader::default();
        entry.virtual_size = section.virtual_size;
        entry.virtual_address = RVA(section.rva);
        pe.write_val(table + index * size_of::<ImageSectionHeader>(), &entry)
            .unwrap();
    }

    pe.as_slice()[..table + sections.len() * size_of::<ImageSectionHeader>()].to_vec()
}

impl Image {
    fn new(pe: &VecPE) -> Self {
        let base = pe.get_image_base().unwrap();
        let size = pe.calculate_memory_size().unwrap() as u64;
        let entrypoint = pe.get_entrypoint().unwrap().0;
        let subsystem = pe.get_nt_headers_64().unwrap().optional_header.subsystem;

        let (exceptions_rva, exceptions_size) = pe
            .get_data_directory(ImageDirectoryEntry::Exception)
            .map(|directory| (directory.virtual_address.0, directory.size))
            .unwrap_or((0, 0));

        let mut blob = Vec::new();

        let mut sections = Vec::new();

        for section in pe.get_section_table().unwrap() {
            let offset = blob.len() as u32;
            let size = section.size_of_raw_data;

            blob.extend_from_slice(section.read(pe).unwrap());

            sections.push(Section {
                rva: section.virtual_address.0,
                virtual_size: section.virtual_size,
                offset,
                size,
                characteristics: section.characteristics,
            });
        }

        let header = generate_header(&sections);

        let mut relocations = Vec::new();

        if let Ok(directory) = RelocationDirectory::parse(pe) {
            if let Ok(entries) = directory.relocations(pe, base) {
                for (rva, value) in entries {
                    if matches!(value, RelocationValue::Relocation64(_)) {
                        relocations.push(rva.0);
                    }
                }
            }
        }

        relocations.sort_unstable();

        let mut names = Vec::new();
        let mut imports = Vec::new();

        if let Ok(directory) = ImportDirectory::parse(pe) {
            for descriptor in directory.descriptors {
                let name = descriptor.get_name(pe).unwrap();

                let module = names.len() as u32;
                names.extend_from_slice(name.as_str().unwrap().as_bytes());
                names.push(0);

                let mut slot = descriptor.first_thunk.0;

                for data in descriptor.get_imports(pe).unwrap() {
                    let symbol = match data {
                        ImportData::ImportByName(name) => {
                            let offset = names.len() as u32;
                            names.extend_from_slice(name.as_bytes());
                            names.push(0);
                            Symbol::Name(offset)
                        }
                        ImportData::Ordinal(ordinal) => Symbol::Ordinal(ordinal as u16),
                    };
                    imports.push(Import {
                        slot,
                        module,
                        symbol,
                    });
                    slot += size_of::<u64>() as u32;
                }
            }
        }

        Image {
            size,
            base,
            entrypoint,
            exceptions_rva,
            exceptions_size,
            subsystem,
            header,
            blob,
            sections,
            relocations,
            names,
            imports,
        }
    }
}

fn protection(characteristics: SectionCharacteristics) -> u64 {
    let execute = characteristics.contains(SectionCharacteristics::MEM_EXECUTE);
    let read = characteristics.contains(SectionCharacteristics::MEM_READ);
    let write = characteristics.contains(SectionCharacteristics::MEM_WRITE);

    match (execute, read, write) {
        (true, true, true) => PAGE_EXECUTE_READWRITE,
        (true, true, false) => PAGE_EXECUTE_READ,
        (true, false, _) => PAGE_EXECUTE,
        (false, true, true) => PAGE_READWRITE,
        (false, true, false) => PAGE_READONLY,
        _ => PAGE_NOACCESS,
    }
}

fn generate_loader(engine: &mut Engine, image: &Image) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();

    instructions.extend(reserve(0x40));

    instructions.extend(import(engine, ImportDef::VirtualAlloc));
    // lpAddress -> RCX
    instructions.extend(set_register(VMReg::Rcx, 0));
    // dwSize -> RDX
    instructions.extend(set_register(VMReg::Rdx, image.size));
    // flAllocationType -> R8
    instructions.extend(set_register(VMReg::R8, MEM_COMMIT | MEM_RESERVE));
    // flProtect -> R9
    instructions.extend(set_register(VMReg::R9, PAGE_READWRITE));
    // VirtualAlloc
    instructions.extend(invoke(VMReg::Rax));
    instructions.extend(load_register(VMReg::Rax));
    instructions.extend(store_register(VMReg::R13));

    // Copy headers:
    let header = engine
        .rt
        .lookup(engine.rt.data_labels[&DataDef::VmLoaderHeader]) as i32;

    instructions.extend(compute_memory(
        VMReg::VImage,
        VMReg::None,
        1,
        header,
        VMSeg::None,
    ));
    instructions.extend(store_register(VMReg::Rdx));
    instructions.extend(load_register(VMReg::R13));
    instructions.extend(store_register(VMReg::R8));
    instructions.extend(foreach(
        engine,
        VMReg::Rax,
        Bound::Immediate(image.header.len()),
        8,
        |_| {
            let mut body = Vec::<Box<dyn Encode>>::new();
            body.extend(load_memory(
                VMReg::Rdx,
                VMReg::Rax,
                1,
                0,
                VMSeg::None,
                VMWidth::Lower64,
            ));
            body.extend(compute_memory(VMReg::R8, VMReg::Rax, 1, 0, VMSeg::None));
            body.push(Box::new(StoreMemory {
                width: VMWidth::Lower64,
            }));
            body
        },
    ));

    // Copy sections:
    let blob = engine
        .rt
        .lookup(engine.rt.data_labels[&DataDef::VmLoaderSections]) as i32;

    for section in &image.sections {
        if section.size == 0 {
            continue;
        }

        instructions.extend(compute_memory(
            VMReg::VImage,
            VMReg::None,
            1,
            blob + section.offset as i32,
            VMSeg::None,
        ));
        instructions.extend(store_register(VMReg::Rdx));

        instructions.extend(compute_memory(
            VMReg::R13,
            VMReg::None,
            1,
            section.rva as i32,
            VMSeg::None,
        ));
        instructions.extend(store_register(VMReg::R8));

        instructions.extend(foreach(
            engine,
            VMReg::Rax,
            Bound::Immediate(section.size as usize),
            8,
            |_| {
                let mut body = Vec::<Box<dyn Encode>>::new();
                body.extend(load_memory(
                    VMReg::Rdx,
                    VMReg::Rax,
                    1,
                    0,
                    VMSeg::None,
                    VMWidth::Lower64,
                ));
                body.extend(compute_memory(VMReg::R8, VMReg::Rax, 1, 0, VMSeg::None));
                body.push(Box::new(StoreMemory {
                    width: VMWidth::Lower64,
                }));
                body
            },
        ));
    }

    // Compute relocation delta:
    instructions.extend(load_register(VMReg::R13));
    instructions.extend(immediate(image.base));
    instructions.extend(sub(None, None));
    instructions.extend(store_register(VMReg::Rcx));

    // Apply relocations:
    for &rva in &image.relocations {
        instructions.extend(load_memory(
            VMReg::R13,
            VMReg::None,
            1,
            rva as i32,
            VMSeg::None,
            VMWidth::Lower64,
        ));
        instructions.extend(load_register(VMReg::Rcx));
        instructions.extend(add(None, None));
        instructions.extend(compute_memory(
            VMReg::R13,
            VMReg::None,
            1,
            rva as i32,
            VMSeg::None,
        ));
        instructions.push(Box::new(StoreMemory {
            width: VMWidth::Lower64,
        }));
    }

    // Resolve import address table:
    let names = engine
        .rt
        .lookup(engine.rt.data_labels[&DataDef::VmLoaderNames]) as i32;

    for entry in &image.imports {
        instructions.extend(import(engine, ImportDef::LoadLibraryA));
        // lpLibFileName -> RCX
        instructions.extend(compute_memory(
            VMReg::VImage,
            VMReg::None,
            1,
            names + entry.module as i32,
            VMSeg::None,
        ));
        instructions.extend(store_register(VMReg::Rcx));
        // LoadLibraryA
        instructions.extend(invoke(VMReg::Rax));
        instructions.extend(load_register(VMReg::Rax));
        instructions.extend(store_register(VMReg::R14));

        instructions.extend(import(engine, ImportDef::GetProcAddress));
        // hModule -> RCX
        instructions.extend(load_register(VMReg::R14));
        instructions.extend(store_register(VMReg::Rcx));

        // lpProcName -> RDX
        match entry.symbol {
            Symbol::Name(offset) => {
                instructions.extend(compute_memory(
                    VMReg::VImage,
                    VMReg::None,
                    1,
                    names + offset as i32,
                    VMSeg::None,
                ));
                instructions.extend(store_register(VMReg::Rdx));
            }
            Symbol::Ordinal(ordinal) => {
                instructions.extend(set_register(VMReg::Rdx, ordinal as u64));
            }
        }
        // GetProcAddress
        instructions.extend(invoke(VMReg::Rax));

        instructions.extend(load_register(VMReg::Rax));
        instructions.extend(compute_memory(
            VMReg::R13,
            VMReg::None,
            1,
            entry.slot as i32,
            VMSeg::None,
        ));
        instructions.push(Box::new(StoreMemory {
            width: VMWidth::Lower64,
        }));
    }

    // Register exceptions table:
    if image.exceptions_rva != 0 && image.exceptions_size != 0 {
        let count = (image.exceptions_size / size_of::<RuntimeFunction>() as u32) as u64;

        instructions.extend(import(engine, ImportDef::RtlAddFunctionTable));
        // FunctionTable -> RCX
        instructions.extend(compute_memory(
            VMReg::R13,
            VMReg::None,
            1,
            image.exceptions_rva as i32,
            VMSeg::None,
        ));
        instructions.extend(store_register(VMReg::Rcx));
        // EntryCount -> RDX
        instructions.extend(set_register(VMReg::Rdx, count));
        // BaseAddress -> R8
        instructions.extend(load_register(VMReg::R13));
        instructions.extend(store_register(VMReg::R8));
        // RtlAddFunctionTable
        instructions.extend(invoke(VMReg::Rax));
    }

    // Restore page protections:
    for section in &image.sections {
        let size = (section.virtual_size + 0xFFF) & !0xFFF;

        instructions.extend(import(engine, ImportDef::VirtualProtect));
        // lpAddress -> RCX
        instructions.extend(compute_memory(
            VMReg::R13,
            VMReg::None,
            1,
            section.rva as i32,
            VMSeg::None,
        ));
        instructions.extend(store_register(VMReg::Rcx));
        // dwSize -> RDX
        instructions.extend(set_register(VMReg::Rdx, size as u64));
        // flNewProtect -> R8
        instructions.extend(set_register(VMReg::R8, protection(section.characteristics)));
        // ALLOCATE lpflOldProtect
        instructions.extend(compute_memory(
            VMReg::Rsp,
            VMReg::None,
            1,
            0x20,
            VMSeg::None,
        ));
        // ALLOCATE lpflOldProtect -> R9
        instructions.extend(store_register(VMReg::R9));
        // VirtualProtect
        instructions.extend(invoke(VMReg::Rax));
    }

    instructions.extend(release(0x40));

    // Publish mapped base to the PEB:
    instructions.extend(load_memory(
        VMReg::None,
        VMReg::None,
        1,
        0x60,
        VMSeg::Gs,
        VMWidth::Lower64,
    ));
    instructions.extend(store_register(VMReg::Rax));
    instructions.extend(load_register(VMReg::R13));
    instructions.extend(compute_memory(
        VMReg::Rax,
        VMReg::None,
        1,
        0x10,
        VMSeg::None,
    ));
    instructions.push(Box::new(StoreMemory {
        width: VMWidth::Lower64,
    }));

    // Compute original entry point:
    instructions.extend(compute_memory(
        VMReg::R13,
        VMReg::None,
        1,
        image.entrypoint as i32,
        VMSeg::None,
    ));
    instructions.extend(store_register(VMReg::Vg0));

    instructions
}

struct Packer {
    image: Image,
}

impl Protection for Packer {
    fn initialize(&mut self, engine: &mut Engine) {
        engine
            .rt
            .define_data_bytes(DataDef::VmLoaderProgram, &[0u8; 4]);
        engine
            .rt
            .define_data_bytes(DataDef::VmLoaderHeader, &self.image.header);
        engine
            .rt
            .define_data_bytes(DataDef::VmLoaderSections, &self.image.blob);
        engine
            .rt
            .define_data_bytes(DataDef::VmLoaderNames, &self.image.names);

        engine.rt.define_data_bytes(DataDef::VmTable, &[]);

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

        let operations = generate_loader(engine, &self.image);

        assemble_bytecode(engine, operations, 0, true);

        create_attestation(engine, 0, true);
    }

    fn apply(&self, engine: &mut Engine) {
        let operations = generate_loader(engine, &self.image);

        let loader = assemble_bytecode(engine, operations, 0, false);

        let (base, _) = create_bytecode(engine, &[loader]);

        write_displacement(engine, DataDef::VmLoaderProgram, base);

        let entrypoint = engine
            .rt
            .lookup(engine.rt.function_labels[&FnDef::VmLoader]) as u32;

        engine
            .pe
            .get_mut_nt_headers_64_ref()
            .unwrap()
            .optional_header
            .address_of_entry_point = RVA(entrypoint);
    }
}

fn stub(subsystem: u16) -> VecPE {
    let mut pe = VecPE::new_disk(SIZE_OF_HEADERS);

    pe.write_val(0, &ImageDOSHeader::default()).unwrap();

    let e_lfanew = pe.e_lfanew().unwrap();

    let mut headers = ImageNTHeaders64::default();
    headers.optional_header.subsystem = subsystem;
    headers.optional_header.size_of_headers = SIZE_OF_HEADERS as u32;
    headers.optional_header.size_of_image = headers.optional_header.section_alignment;

    pe.write_val(e_lfanew.0 as usize, &headers).unwrap();

    pe
}

pub fn pack(input: &Engine) -> Vec<u8> {
    let image = Image::new(&input.pe);

    info!(
        "Packing image 0x{:X} ({} sections, {} relocations, {} imports)",
        image.size,
        image.sections.len(),
        image.relocations.len(),
        image.imports.len(),
    );

    let mut output = Engine::wrap(stub(image.subsystem), input.args);
    output.attach(Packer { image });
    output.execute()
}
