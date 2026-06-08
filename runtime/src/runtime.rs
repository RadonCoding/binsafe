use std::collections::HashMap;

use iced_x86::{
    code_asm::{rcx, CodeAssembler, CodeLabel},
    BlockEncoderOptions, Decoder, DecoderOptions, Encoder,
};
use rand::seq::SliceRandom;

use crate::{
    functions,
    mapper::{mapped, Mappable, Mapper},
    vm::{
        self,
        bytecode::{VMOp, VMReg},
    },
};

mapped! {
    FnDef {
        /* VM */
        VmGInit,
        VmTInit,
        VmEntry,
        VmExit,
        VmCrypt,
        VmDispatch,
        VmLookup,
        VmCleanup,
        VmRegistersCapture,
        VmRegistersRestore,
        VmVectorsCapture,
        VmVectorsRestore,
        /* VM HANDLERS */
        VmFunctionsInitialize,
        VmHandlersInitialize,
        VmHandlerJcc,
        VmHandlerRet,
        VmHandlerLoadImmediate,
        VmHandlerLoadRegister,
        VmHandlerLoadMemory,
        VmHandlerLoadAddress,
        VmHandlerStoreRegister,
        VmHandlerStoreMemory,
        VmHandlerLoadVector,
        VmHandlerStoreVector,
        VmHandlerAdd,
        VmHandlerSub,
        VmHandlerAnd,
        VmHandlerOr,
        VmHandlerXor,
        VmHandlerTest,
        VmHandlerRol,
        VmHandlerRor,
        VmHandlerShl,
        VmHandlerShr,
        VmHandlerSar,
        VmHandlerMul,
        VmHandlerTrailingZeros,
        VmHandlerPush,
        VmHandlerPop,
        VmHandlerDiscard,
        VmHandlerPackedByteMask,
        VmHandlerPackedByteEqual,
        VmHandlerVectorAnd,
        VmHandlerVectorOr,
        VmHandlerVectorXor,
        VmHandlerVectorAndNot,
        /* VM ARITHMETIC */
        VmFlags,
        /* VM VEH */
        VmVehInitialize,
        VmVehHandler,
        /* CORE */
        CompareUnicodeToAnsi,
        CompareAnsiToAnsi,
        Resolve,
        #[cfg(debug_assertions)]
        Strlen,
        #[cfg(debug_assertions)]
        Print,
        #[cfg(debug_assertions)]
        Fmtdec,
    }
}

mapped! {
    DataDef {
        Functions,
        VehStart,
        VmHandlers,
        VmGlobalRegisters,
        VmRegistersTlsIndex,
        VmVectorsTlsIndex,
        VmKeyTlsIndex,
        VmCleanupFlsIndex,
        VmTable,
        VmCode,
        VmKeySeed,
        VmKeyMul,
        VmKeyAdd,
        VehEnd,
        ImportAddresses,
        ImportNames,
    }
}

mapped! {
    BoolDef {
        VmIsLocked,
        VmHasVeh,
    }
}

mapped! {
    StringDef {
        Ntdll,
        KERNEL32,
        KERNELBASE,
        RtlAddVectoredExceptionHandler,
        TlsAlloc,
        RtlFlsAlloc,
        RtlFlsSetValue,
        GetProcessHeap,
        RtlAllocateHeap,
        RtlFreeHeap,
        NtSetInformationThread,
        NtQueryInformationThread,
        #[cfg(debug_assertions)]
        NtWriteFile,
    }
}

mapped! {
    ImportDef {
        RtlAddVectoredExceptionHandler,
        TlsAlloc,
        RtlFlsAlloc,
        RtlFlsSetValue,
        GetProcessHeap,
        RtlAllocateHeap,
        RtlFreeHeap,
        NtSetInformationThread,
        NtQueryInformationThread,
        #[cfg(debug_assertions)]
        NtWriteFile,
    }
}

impl ImportDef {
    pub fn get(&self) -> (StringDef, StringDef) {
        match self {
            ImportDef::RtlAddVectoredExceptionHandler { .. } => {
                (StringDef::Ntdll, StringDef::RtlAddVectoredExceptionHandler)
            }
            ImportDef::TlsAlloc { .. } => (StringDef::KERNEL32, StringDef::TlsAlloc),
            ImportDef::RtlFlsAlloc { .. } => (StringDef::Ntdll, StringDef::RtlFlsAlloc),
            ImportDef::RtlFlsSetValue { .. } => (StringDef::Ntdll, StringDef::RtlFlsSetValue),
            ImportDef::GetProcessHeap { .. } => (StringDef::KERNEL32, StringDef::GetProcessHeap),
            ImportDef::RtlAllocateHeap { .. } => (StringDef::Ntdll, StringDef::RtlAllocateHeap),
            ImportDef::RtlFreeHeap { .. } => (StringDef::Ntdll, StringDef::RtlFreeHeap),
            ImportDef::NtSetInformationThread { .. } => {
                (StringDef::Ntdll, StringDef::NtSetInformationThread)
            }
            ImportDef::NtQueryInformationThread { .. } => {
                (StringDef::Ntdll, StringDef::NtQueryInformationThread)
            }
            #[cfg(debug_assertions)]
            ImportDef::NtWriteFile { .. } => (StringDef::Ntdll, StringDef::NtWriteFile),
        }
    }
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
    pub string_labels: HashMap<StringDef, CodeLabel>,
    strings: HashMap<StringDef, Vec<u8>>,
    imports: HashMap<ImportDef, usize>,
    addresses: HashMap<CodeLabel, u64>,
    fixups: HashMap<CodeLabel, (CodeLabel, u64, Option<usize>)>,
    chains: Vec<usize>,
    pub mapper: Mapper,
}

impl Runtime {
    pub fn new(bitness: u32) -> Self {
        let mut asm = CodeAssembler::new(bitness).unwrap();

        let mut func_labels = HashMap::new();

        for def in FnDef::VARIANTS {
            func_labels.insert(*def, asm.create_label());
        }

        let mut data_labels = HashMap::new();

        for def in DataDef::VARIANTS {
            data_labels.insert(*def, asm.create_label());
        }

        let mut bool_labels = HashMap::new();

        for def in BoolDef::VARIANTS {
            bool_labels.insert(*def, asm.create_label());
        }

        let mut string_labels = HashMap::new();

        for def in StringDef::VARIANTS {
            string_labels.insert(*def, asm.create_label());
        }

        let mut imports = HashMap::new();

        for (i, def) in ImportDef::VARIANTS.iter().enumerate() {
            imports.insert(*def, i);
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
            imports,
            addresses: HashMap::new(),
            fixups: HashMap::new(),
            mapper: Mapper::new(),
            chains: Vec::new(),
        }
    }

    pub fn with_chain<F>(&mut self, f: F)
    where
        F: FnOnce(&mut Self),
    {
        let id = self.fixups.len();

        self.chains.push(id);

        f(self);

        self.chains.pop();
    }

    pub fn mark_as_encrypted(&mut self, target: CodeLabel) -> u64 {
        let mut label = self.asm.create_label();
        self.asm.set_label(&mut label).unwrap();
        let key = rand::random::<u64>();
        let chain = self.chains.last().copied();
        self.fixups.insert(label, (target, key, chain));
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

    pub fn resolve(&mut self, def: ImportDef) {
        // mov rcx, ...
        self.asm.mov(rcx, self.mapper.index(def) as u64).unwrap();

        // call ...
        self.asm.call(self.func_labels[&FnDef::Resolve]).unwrap();
    }

    pub fn assemble(&mut self, ip: u64) -> Vec<u8> {
        let mut shuffled = Vec::new();

        let functions: Vec<(FnDef, fn(&mut Runtime))> = vec![
            (FnDef::VmGInit, vm::functions::ginit::build),
            (FnDef::VmTInit, vm::functions::tinit::build),
            (FnDef::VmEntry, vm::functions::entry::build),
            (FnDef::VmExit, vm::functions::exit::build),
            (FnDef::VmCrypt, vm::functions::crypt::build),
            (FnDef::VmDispatch, vm::functions::dispatch::build),
            (FnDef::VmLookup, vm::functions::lookup::build),
            (FnDef::VmCleanup, vm::functions::cleanup::build),
            (FnDef::VmRegistersCapture, vm::functions::registers::capture),
            (FnDef::VmRegistersRestore, vm::functions::registers::restore),
            (FnDef::VmVectorsCapture, vm::functions::vectors::capture),
            (FnDef::VmVectorsRestore, vm::functions::vectors::restore),
            (FnDef::VmFunctionsInitialize, vm::functions::initialize),
            (FnDef::VmHandlersInitialize, vm::handlers::initialize),
            (FnDef::VmHandlerJcc, vm::handlers::jcc::build),
            (FnDef::VmHandlerRet, vm::handlers::ret::build),
            (
                FnDef::VmHandlerLoadImmediate,
                vm::handlers::load_immediate::build,
            ),
            (
                FnDef::VmHandlerLoadRegister,
                vm::handlers::load_register::build,
            ),
            (FnDef::VmHandlerLoadMemory, vm::handlers::load_memory::build),
            (
                FnDef::VmHandlerLoadAddress,
                vm::handlers::load_address::build,
            ),
            (
                FnDef::VmHandlerStoreRegister,
                vm::handlers::store_register::build,
            ),
            (
                FnDef::VmHandlerStoreMemory,
                vm::handlers::store_memory::build,
            ),
            (FnDef::VmHandlerLoadVector, vm::handlers::load_vector::build),
            (
                FnDef::VmHandlerStoreVector,
                vm::handlers::store_vector::build,
            ),
            (FnDef::VmHandlerAdd, vm::handlers::add::build),
            (FnDef::VmHandlerSub, vm::handlers::sub::build),
            (FnDef::VmHandlerAnd, vm::handlers::and::build),
            (FnDef::VmHandlerOr, vm::handlers::or::build),
            (FnDef::VmHandlerXor, vm::handlers::xor::build),
            (FnDef::VmHandlerTest, vm::handlers::test::build),
            (FnDef::VmHandlerRol, vm::handlers::rol::build),
            (FnDef::VmHandlerRor, vm::handlers::ror::build),
            (FnDef::VmHandlerShl, vm::handlers::shl::build),
            (FnDef::VmHandlerShr, vm::handlers::shr::build),
            (FnDef::VmHandlerSar, vm::handlers::sar::build),
            (FnDef::VmHandlerMul, vm::handlers::mul::build),
            (FnDef::VmHandlerTrailingZeros, vm::handlers::trailing_zeros::build),
            (FnDef::VmHandlerPush, vm::handlers::push::build),
            (FnDef::VmHandlerPop, vm::handlers::pop::build),
            (FnDef::VmHandlerDiscard, vm::handlers::discard::build),
            (FnDef::VmHandlerPackedByteMask, vm::handlers::packed_byte_mask::build),
            (FnDef::VmHandlerPackedByteEqual, vm::handlers::packed_byte_equal::build),
            (FnDef::VmHandlerVectorAnd, vm::handlers::vector_and::build),
            (FnDef::VmHandlerVectorOr, vm::handlers::vector_or::build),
            (FnDef::VmHandlerVectorXor, vm::handlers::vector_xor::build),
            (FnDef::VmHandlerVectorAndNot, vm::handlers::vector_and_not::build),
            (FnDef::VmFlags, vm::handlers::flags::build),
            (FnDef::VmVehInitialize, vm::functions::veh::initialize),
            (
                FnDef::CompareUnicodeToAnsi,
                functions::compare_unicode_to_ansi::build,
            ),
            (
                FnDef::CompareAnsiToAnsi,
                functions::compare_ansi_to_ansi::build,
            ),
            (FnDef::Resolve, functions::resolve::build),
            #[cfg(debug_assertions)]
            (FnDef::Strlen, functions::strlen::build),
            #[cfg(debug_assertions)]
            (FnDef::Print, functions::print::build),
            #[cfg(debug_assertions)]
            (FnDef::Fmtdec, functions::fmtdec::build),
        ];

        self.define_data_byte(DataDef::VehStart, 0x0);
        self.define_data_byte(DataDef::VehEnd, 0x0);

        self.define_data_bytes(DataDef::Functions, &vec![0u8; FnDef::COUNT * 8]);
        self.define_data_bytes(DataDef::VmHandlers, &[0u8; VMOp::COUNT * 8]);
        self.define_data_bytes(DataDef::VmGlobalRegisters, &[0u8; VMReg::COUNT * 8]);

        self.define_data_dword(DataDef::VmRegistersTlsIndex, 0);
        self.define_data_dword(DataDef::VmVectorsTlsIndex, 0);
        self.define_data_dword(DataDef::VmKeyTlsIndex, 0);
        self.define_data_dword(DataDef::VmCleanupFlsIndex, 0);

        self.define_data_bytes(DataDef::ImportAddresses, &vec![0u8; self.imports.len() * 8]);
        self.define_data_bytes(DataDef::ImportNames, &vec![0u8; self.imports.len() * 16]);

        self.define_bool(BoolDef::VmIsLocked, false);
        self.define_bool(BoolDef::VmHasVeh, false);

        self.define_string(StringDef::Ntdll, "ntdll.dll");
        self.define_string(StringDef::KERNEL32, "KERNEL32.DLL");
        self.define_string(StringDef::KERNELBASE, "KERNELBASE.DLL");
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
        self.define_string(StringDef::NtSetInformationThread, "NtSetInformationThread");
        self.define_string(
            StringDef::NtQueryInformationThread,
            "NtQueryInformationThread",
        );
        #[cfg(debug_assertions)]
        self.define_string(StringDef::NtWriteFile, "NtWriteFile");

        for (def, builder) in functions {
            shuffled.push(EmissionTask::Function(def, builder));
        }

        for def in DataDef::VARIANTS {
            if *def == DataDef::Functions || *def == DataDef::VehStart || *def == DataDef::VehEnd {
                continue;
            }

            if self.data.contains_key(def) {
                shuffled.push(EmissionTask::Data(*def));
            }
        }

        for def in BoolDef::VARIANTS {
            if self.bools.contains_key(def) {
                shuffled.push(EmissionTask::Bool(*def));
            }
        }

        for def in StringDef::VARIANTS {
            if self.strings.contains_key(def) {
                shuffled.push(EmissionTask::String(*def));
            }
        }

        let mut rng = rand::thread_rng();
        shuffled.shuffle(&mut rng);

        let mut tasks = Vec::new();
        tasks.push(EmissionTask::Data(DataDef::Functions));
        tasks.push(EmissionTask::Function(
            FnDef::VmVehHandler,
            vm::functions::veh::handler,
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

                    if self.data[&def].is_empty() {
                        self.asm.zero_bytes().unwrap();
                    } else {
                        self.asm.db(&self.data[&def]).unwrap();
                    }
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
