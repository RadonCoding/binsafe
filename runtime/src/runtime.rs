use std::collections::HashMap;

use iced_x86::{
    code_asm::{ptr, r10, r11, rcx, AsmRegister64, CodeAssembler, CodeLabel},
    BlockEncoderOptions,
};
use rand::{seq::SliceRandom, Rng};

use crate::{
    functions,
    mapper::{mapped, Mappable, Mapper},
    vm::{
        self,
        bytecode::{VMReg, VMVec},
    },
};

mapped! {
    FnDef {
        /* VM */
        VmContextCreate,
        VmContextDelete,
        VmGInit,
        VmTInit,
        VmEntry,
        VmExit,
        VmCrypt,
        VmDispatch,
        VmInvoke,
        VmLookup,
        VmCleanup,
        VmRegistersCapture,
        VmRegistersCaptureVolatile,
        VmRegistersCaptureNonvolatile,
        VmRegistersRestore,
        VmRegistersCopy,
        VmVectorsAvx,
        VmVectorsCapture,
        VmVectorsRestore,
        VmVectorsCopy,
        VmFlags,
        /* VM HANDLERS */
        VmHandlerJcc,
        VmHandlerRet,
        VmHandlerLoadImmediate,
        VmHandlerLoadRegister,
        VmHandlerLoadMemory,
        VmHandlerLoadAddress,
        VmHandlerStoreRegister,
        VmHandlerStoreMemory,
        VmHandlerLoadVector,
        VmHandlerStoreMerge,
        VmHandlerStoreExtend,
        VmHandlerAdd,
        VmHandlerSub,
        VmHandlerAnd,
        VmHandlerOr,
        VmHandlerXor,
        VmHandlerRol,
        VmHandlerRor,
        VmHandlerShl,
        VmHandlerShr,
        VmHandlerSar,
        VmHandlerMul,
        VmHandlerDiv,
        VmHandlerTrailingZeros,
        VmHandlerBitScanReverse,
        VmHandlerByteSwap,
        VmHandlerBitTest,
        VmHandlerBitTestSet,
        VmHandlerBitTestReset,
        VmHandlerBitTestComplement,
        VmHandlerExchange,
        VmHandlerExchangeAdd,
        VmHandlerCompareExchange,
        VmHandlerPush,
        VmHandlerPop,
        VmHandlerDiscard,
        VmHandlerPackedByteMask,
        VmHandlerPackedByteEqual,
        VmHandlerVectorAnd,
        VmHandlerVectorAndNot,
        VmHandlerVectorOr,
        VmHandlerVectorXor,
        VmHandlerVectorAdd,
        VmHandlerVectorSub,
        VmHandlerVectorMul,
        VmHandlerVectorDiv,
        VmHandlerTimestamp,
        /* VM VEH */
        VmVehInitialize,
        VmVehHandler,
        /* CORE */
        Hash,
        Resolve,
        #[cfg(debug_assertions)]
        Strlen,
        #[cfg(debug_assertions)]
        Print,
        #[cfg(debug_assertions)]
        Format,
    }
}

mapped! {
    DataDef {
        VehStart,
        VmGlobalRegisters,
        VmGlobalVectors,
        VmRegistersTlsIndex,
        VmKeyTlsIndex,
        #[cfg(debug_assertions)]
        VmDebugTlsIndex,
        VmCleanupFlsIndex,
        VmTable,
        VmCode,
        VmAttestation,
        VmTrampolines,
        VmKeySeed,
        VmKeyMul,
        VmKeyAdd,
        VehEnd,
        ImportAddresses,
        ImportNames,
        Functions
    }
}

mapped! {
    BoolDef {
        IsLocked,
        HasAvx,
        HasVeh,
        #[cfg(debug_assertions)]
        IsDebugged
    }
}

mapped! {
    StringDef {
        User32,
        Tampered
    }
}

mapped! {
    HashDef {
        Ntdll,
        Kernel32,
        KernelBase,
        User32,
        LoadLibraryA,
        RtlAddVectoredExceptionHandler,
        TlsAlloc,
        RtlFlsAlloc,
        RtlFlsSetValue,
        GetProcessHeap,
        RtlAllocateHeap,
        RtlFreeHeap,
        NtQuerySystemInformation,
        NtQueryInformationProcess,
        NtSetInformationThread,
        NtQueryInformationThread,
        MessageBoxA,
        NtTerminateProcess,
        #[cfg(debug_assertions)]
        AllocConsole,
        #[cfg(debug_assertions)]
        NtWriteFile,
    }
}

mapped! {
    ImportDef {
        LoadLibraryA,
        RtlAddVectoredExceptionHandler,
        TlsAlloc,
        RtlFlsAlloc,
        RtlFlsSetValue,
        GetProcessHeap,
        RtlAllocateHeap,
        RtlFreeHeap,
        NtQuerySystemInformation,
        NtQueryInformationProcess,
        NtSetInformationThread,
        NtQueryInformationThread,
        MessageBoxA,
        NtTerminateProcess,
        #[cfg(debug_assertions)]
        AllocConsole,
        #[cfg(debug_assertions)]
        NtWriteFile,
    }
}

impl ImportDef {
    pub fn get(&self) -> (HashDef, HashDef) {
        match self {
            ImportDef::LoadLibraryA { .. } => (HashDef::KernelBase, HashDef::LoadLibraryA),
            ImportDef::RtlAddVectoredExceptionHandler { .. } => {
                (HashDef::Ntdll, HashDef::RtlAddVectoredExceptionHandler)
            }
            ImportDef::TlsAlloc { .. } => (HashDef::Kernel32, HashDef::TlsAlloc),
            ImportDef::RtlFlsAlloc { .. } => (HashDef::Ntdll, HashDef::RtlFlsAlloc),
            ImportDef::RtlFlsSetValue { .. } => (HashDef::Ntdll, HashDef::RtlFlsSetValue),
            ImportDef::GetProcessHeap { .. } => (HashDef::Kernel32, HashDef::GetProcessHeap),
            ImportDef::RtlAllocateHeap { .. } => (HashDef::Ntdll, HashDef::RtlAllocateHeap),
            ImportDef::RtlFreeHeap { .. } => (HashDef::Ntdll, HashDef::RtlFreeHeap),
            ImportDef::NtQuerySystemInformation { .. } => {
                (HashDef::Ntdll, HashDef::NtQuerySystemInformation)
            }
            ImportDef::NtQueryInformationProcess { .. } => {
                (HashDef::Ntdll, HashDef::NtQueryInformationProcess)
            }
            ImportDef::NtSetInformationThread { .. } => {
                (HashDef::Ntdll, HashDef::NtSetInformationThread)
            }
            ImportDef::NtQueryInformationThread { .. } => {
                (HashDef::Ntdll, HashDef::NtQueryInformationThread)
            }
            ImportDef::MessageBoxA { .. } => (HashDef::User32, HashDef::MessageBoxA),
            ImportDef::NtTerminateProcess { .. } => (HashDef::Ntdll, HashDef::NtTerminateProcess),
            #[cfg(debug_assertions)]
            ImportDef::AllocConsole { .. } => (HashDef::KernelBase, HashDef::AllocConsole),
            #[cfg(debug_assertions)]
            ImportDef::NtWriteFile { .. } => (HashDef::Ntdll, HashDef::NtWriteFile),
        }
    }
}

#[derive(Clone, Copy)]
enum EmissionTask {
    Function(FnDef, fn(&mut Runtime)),
    Data(DataDef),
    Bool(BoolDef),
    String(StringDef),
    Hash(HashDef),
    DispatchTable(usize),
    DispatchStub(usize, usize),
}

struct Dispatch {
    table: CodeLabel,
    stubs: Vec<(u8, CodeLabel, CodeLabel)>,
}

impl Dispatch {
    fn slots(&self) -> usize {
        self.stubs
            .iter()
            .map(|(i, _, _)| *i as usize)
            .max()
            .map(|m| m + 1)
            .unwrap_or(0)
    }
}

pub struct Runtime {
    pub asm: CodeAssembler,

    pub nonce: u64,

    pub function_labels: HashMap<FnDef, CodeLabel>,
    pub data_labels: HashMap<DataDef, CodeLabel>,
    pub bool_labels: HashMap<BoolDef, CodeLabel>,
    pub string_labels: HashMap<StringDef, CodeLabel>,
    pub hash_labels: HashMap<HashDef, CodeLabel>,

    data: HashMap<DataDef, Vec<u8>>,
    bools: HashMap<BoolDef, bool>,
    strings: HashMap<StringDef, Vec<u8>>,
    hashes: HashMap<HashDef, Vec<u8>>,

    imports: HashMap<ImportDef, usize>,

    dispatches: Vec<Dispatch>,

    functions: HashMap<FnDef, (usize, usize)>,

    addresses: HashMap<CodeLabel, u64>,
    sizes: HashMap<CodeLabel, u64>,

    pub mapper: Mapper,
}

impl Runtime {
    pub fn new(bitness: u32) -> Self {
        let mut asm = CodeAssembler::new(bitness).unwrap();

        let nonce = rand::thread_rng().gen::<u64>();

        let mut function_labels = HashMap::new();

        for def in FnDef::VARIANTS {
            function_labels.insert(*def, asm.create_label());
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

        let mut hash_labels = HashMap::new();

        for def in HashDef::VARIANTS {
            hash_labels.insert(*def, asm.create_label());
        }

        let mut imports = HashMap::new();

        for (i, def) in ImportDef::VARIANTS.iter().enumerate() {
            imports.insert(*def, i);
        }

        Self {
            asm,

            nonce,

            function_labels,
            data_labels,
            bool_labels,
            string_labels,
            hash_labels,

            data: HashMap::new(),
            bools: HashMap::new(),
            strings: HashMap::new(),
            hashes: HashMap::new(),

            imports,

            dispatches: Vec::new(),

            functions: HashMap::new(),

            addresses: HashMap::new(),
            sizes: HashMap::new(),

            mapper: Mapper::new(),
        }
    }

    fn set_function_label(&mut self, def: FnDef) {
        let label = self.function_labels.get_mut(&def).unwrap();
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

    fn set_hash_label(&mut self, def: HashDef) {
        let label = self.hash_labels.get_mut(&def).unwrap();
        self.asm.set_label(label).unwrap();
    }

    fn set_string_label(&mut self, def: StringDef) {
        let label = self.string_labels.get_mut(&def).unwrap();
        self.asm.set_label(label).unwrap();
    }

    pub fn lookup(&self, label: CodeLabel) -> u64 {
        self.addresses[&label]
    }

    pub fn size(&self, label: CodeLabel) -> u64 {
        self.sizes[&label]
    }

    fn hash(&self, value: &str) -> u64 {
        let mut hash = 14695981039346656037u64 ^ self.nonce;

        for byte in value.bytes().map(|b| b.to_ascii_lowercase()) {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }

        hash ^= hash >> 0x21;
        hash = hash.wrapping_mul(0xff51afd7ed558ccd);
        hash ^= hash >> 0x21;
        hash = hash.wrapping_mul(0xc4ceb9fe1a85ec53);
        hash ^= hash >> 0x21;

        hash
    }

    pub fn define_data_byte(&mut self, def: DataDef, data: u8) {
        self.data.entry(def).or_insert_with(|| vec![data]);
    }

    pub fn define_data_bytes(&mut self, def: DataDef, data: &[u8]) {
        self.data.entry(def).or_insert_with(|| data.to_vec());
    }

    pub fn define_data_dword(&mut self, def: DataDef, data: u32) {
        self.data
            .entry(def)
            .or_insert_with(|| data.to_le_bytes().to_vec());
    }

    pub fn define_data_qword(&mut self, def: DataDef, data: u64) {
        self.data
            .entry(def)
            .or_insert_with(|| data.to_le_bytes().to_vec());
    }

    pub fn define_bool(&mut self, def: BoolDef, value: bool) {
        self.bools.entry(def).or_insert(value);
    }

    fn define_string(&mut self, def: StringDef, string: &str) {
        self.strings.entry(def).or_insert_with(|| {
            let mut bytes = string.as_bytes().to_vec();
            bytes.push(0);
            bytes
        });
    }

    fn define_hash(&mut self, def: HashDef, string: &str) {
        let hash = self.hash(string);
        self.hashes
            .entry(def)
            .or_insert(hash.to_le_bytes().to_vec());
    }

    pub fn resolve(&mut self, def: ImportDef) {
        // mov rcx, ...
        self.asm.mov(rcx, self.mapper.index(def) as u64).unwrap();
        // call ...
        self.asm
            .call(self.function_labels[&FnDef::Resolve])
            .unwrap();
    }

    pub fn jumps(&mut self, key: AsmRegister64, cases: Vec<(u8, CodeLabel)>) {
        self.dispatch(key, cases);
    }

    pub fn calls(&mut self, key: AsmRegister64, cases: Vec<(u8, CodeLabel)>) {
        let mut fallback = self.asm.create_label();

        // lea r10, [....]
        self.asm.lea(r10, ptr(fallback)).unwrap();
        // push r10
        self.asm.push(r10).unwrap();

        self.dispatch(key, cases);

        self.asm.set_label(&mut fallback).unwrap();
        self.asm.zero_bytes().unwrap();
    }

    fn dispatch(&mut self, key: AsmRegister64, cases: Vec<(u8, CodeLabel)>) {
        let table = self.asm.create_label();

        let mut stubs = Vec::new();

        // mov r10, ...
        self.asm.mov(r10, key).unwrap();
        // lea r11, [...]
        self.asm.lea(r11, ptr(table)).unwrap();
        // mov r10, [r11 + r10*8]
        self.asm.mov(r10, ptr(r11 + r10 * 8)).unwrap();
        // add r10, r11
        self.asm.add(r10, r11).unwrap();
        // jmp r10
        self.asm.jmp(r10).unwrap();

        for (index, target) in cases {
            let stub = self.asm.create_label();
            stubs.push((index, stub, target));
        }

        self.dispatches.push(Dispatch { table, stubs });
    }

    fn emit(&mut self, tasks: &[EmissionTask]) {
        for &task in tasks {
            match task {
                EmissionTask::Function(def, builder) => {
                    let start = self.asm.instructions().len();
                    self.set_function_label(def);
                    builder(self);
                    let end = self.asm.instructions().len();
                    self.functions.insert(def, (start, end));
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
                EmissionTask::Hash(def) => {
                    self.set_hash_label(def);
                    self.asm.db(&self.hashes[&def]).unwrap();
                }
                EmissionTask::DispatchTable(index) => {
                    let dispatch = &mut self.dispatches[index];

                    self.asm.set_label(&mut dispatch.table).unwrap();

                    for _ in 0..dispatch.slots() {
                        self.asm.dq(&[0u64]).unwrap();
                    }
                }
                EmissionTask::DispatchStub(table, entry) => {
                    let (index, stub, target) =
                        self.dispatches[table].stubs.get_mut(entry).unwrap();

                    self.asm.set_label(stub).unwrap();

                    // lea r10, [...]
                    self.asm.lea(r10, ptr(*target)).unwrap();
                    // sub r10, r11
                    self.asm.sub(r10, r11).unwrap();
                    // mov [r11 + ...], r10
                    self.asm.mov(ptr(r11 + *index as i32 * 8), r10).unwrap();
                    // add r10, r11
                    self.asm.add(r10, r11).unwrap();
                    // jmp r10
                    self.asm.jmp(r10).unwrap();
                }
            }
        }
    }

    pub fn assemble(&mut self, ip: u64) -> Vec<u8> {
        let functions: [(FnDef, fn(&mut Runtime)); FnDef::COUNT - 1] = [
            (FnDef::VmContextCreate, vm::functions::context::create),
            (FnDef::VmContextDelete, vm::functions::context::delete),
            (FnDef::VmGInit, vm::functions::ginit::build),
            (FnDef::VmTInit, vm::functions::tinit::build),
            (FnDef::VmEntry, vm::functions::entry::build),
            (FnDef::VmExit, vm::functions::exit::build),
            (FnDef::VmCrypt, vm::functions::crypt::build),
            (FnDef::VmDispatch, vm::functions::dispatch::build),
            (FnDef::VmInvoke, vm::functions::invoke::build),
            (FnDef::VmLookup, vm::functions::lookup::build),
            (FnDef::VmCleanup, vm::functions::cleanup::build),
            (FnDef::VmRegistersCapture, vm::functions::registers::capture),
            (
                FnDef::VmRegistersCaptureVolatile,
                vm::functions::registers::capture_volatile,
            ),
            (
                FnDef::VmRegistersCaptureNonvolatile,
                vm::functions::registers::capture_nonvolatile,
            ),
            (FnDef::VmRegistersRestore, vm::functions::registers::restore),
            (FnDef::VmRegistersCopy, vm::functions::registers::copy),
            (FnDef::VmVectorsAvx, vm::functions::vectors::avx),
            (FnDef::VmVectorsCapture, vm::functions::vectors::capture),
            (FnDef::VmVectorsRestore, vm::functions::vectors::restore),
            (FnDef::VmVectorsCopy, vm::functions::vectors::copy),
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
            (FnDef::VmHandlerStoreMerge, vm::handlers::store_merge::build),
            (
                FnDef::VmHandlerStoreExtend,
                vm::handlers::store_extend::build,
            ),
            (FnDef::VmHandlerAdd, vm::handlers::add::build),
            (FnDef::VmHandlerSub, vm::handlers::sub::build),
            (FnDef::VmHandlerAnd, vm::handlers::and::build),
            (FnDef::VmHandlerOr, vm::handlers::or::build),
            (FnDef::VmHandlerXor, vm::handlers::xor::build),
            (FnDef::VmHandlerRol, vm::handlers::rol::build),
            (FnDef::VmHandlerRor, vm::handlers::ror::build),
            (FnDef::VmHandlerShl, vm::handlers::shl::build),
            (FnDef::VmHandlerShr, vm::handlers::shr::build),
            (FnDef::VmHandlerSar, vm::handlers::sar::build),
            (FnDef::VmHandlerMul, vm::handlers::mul::build),
            (FnDef::VmHandlerDiv, vm::handlers::div::build),
            (
                FnDef::VmHandlerTrailingZeros,
                vm::handlers::trailing_zeros::build,
            ),
            (
                FnDef::VmHandlerBitScanReverse,
                vm::handlers::bit_scan_reverse::build,
            ),
            (FnDef::VmHandlerByteSwap, vm::handlers::byte_swap::build),
            (FnDef::VmHandlerBitTest, vm::handlers::bit_test::build),
            (
                FnDef::VmHandlerBitTestSet,
                vm::handlers::bit_test_set::build,
            ),
            (
                FnDef::VmHandlerBitTestReset,
                vm::handlers::bit_test_reset::build,
            ),
            (
                FnDef::VmHandlerBitTestComplement,
                vm::handlers::bit_test_complement::build,
            ),
            (FnDef::VmHandlerExchange, vm::handlers::exchange::build),
            (
                FnDef::VmHandlerExchangeAdd,
                vm::handlers::exchange_add::build,
            ),
            (
                FnDef::VmHandlerCompareExchange,
                vm::handlers::compare_exchange::build,
            ),
            (FnDef::VmHandlerPush, vm::handlers::push::build),
            (FnDef::VmHandlerPop, vm::handlers::pop::build),
            (FnDef::VmHandlerDiscard, vm::handlers::discard::build),
            (
                FnDef::VmHandlerPackedByteMask,
                vm::handlers::packed_byte_mask::build,
            ),
            (
                FnDef::VmHandlerPackedByteEqual,
                vm::handlers::packed_byte_equal::build,
            ),
            (FnDef::VmHandlerVectorAnd, vm::handlers::vector_and::build),
            (
                FnDef::VmHandlerVectorAndNot,
                vm::handlers::vector_and_not::build,
            ),
            (FnDef::VmHandlerVectorOr, vm::handlers::vector_or::build),
            (FnDef::VmHandlerVectorXor, vm::handlers::vector_xor::build),
            (FnDef::VmHandlerVectorAdd, vm::handlers::vector_add::build),
            (FnDef::VmHandlerVectorSub, vm::handlers::vector_sub::build),
            (FnDef::VmHandlerVectorMul, vm::handlers::vector_mul::build),
            (FnDef::VmHandlerVectorDiv, vm::handlers::vector_div::build),
            (FnDef::VmHandlerTimestamp, vm::handlers::timestamp::build),
            (FnDef::VmFlags, vm::handlers::flags::build),
            (FnDef::VmVehInitialize, vm::functions::veh::initialize),
            (FnDef::Hash, functions::hash::build),
            (FnDef::Resolve, functions::resolve::build),
            #[cfg(debug_assertions)]
            (FnDef::Strlen, functions::strlen::build),
            #[cfg(debug_assertions)]
            (FnDef::Print, functions::print::build),
            #[cfg(debug_assertions)]
            (FnDef::Format, functions::format::build),
        ];

        self.define_data_byte(DataDef::VehStart, 0x0);
        self.define_data_byte(DataDef::VehEnd, 0x0);

        self.define_data_bytes(DataDef::VmGlobalRegisters, &[0u8; VMReg::COUNT * 8]);
        self.define_data_bytes(DataDef::VmGlobalVectors, &[0u8; VMVec::COUNT * 32]);

        self.define_data_dword(DataDef::VmRegistersTlsIndex, 0);
        self.define_data_dword(DataDef::VmKeyTlsIndex, 0);
        #[cfg(debug_assertions)]
        self.define_data_dword(DataDef::VmDebugTlsIndex, 0);
        self.define_data_dword(DataDef::VmCleanupFlsIndex, 0);

        self.define_data_bytes(DataDef::ImportAddresses, &vec![0u8; self.imports.len() * 8]);
        self.define_data_bytes(DataDef::ImportNames, &vec![0u8; self.imports.len() * 16]);

        self.define_data_bytes(DataDef::Functions, &vec![0u8; FnDef::COUNT * 8]);

        self.define_bool(BoolDef::IsLocked, false);
        self.define_bool(BoolDef::HasAvx, false);
        self.define_bool(BoolDef::HasVeh, false);
        #[cfg(debug_assertions)]
        self.define_bool(BoolDef::IsDebugged, false);

        self.define_string(StringDef::User32, "user32.dll");
        self.define_string(
            StringDef::Tampered,
            "This application has been tampered with or is running in an unsupported environment.",
        );

        self.define_hash(HashDef::Ntdll, "ntdll.dll");
        self.define_hash(HashDef::Kernel32, "kernel32.dll");
        self.define_hash(HashDef::KernelBase, "KernelBase.dll");
        self.define_hash(HashDef::User32, "user32.dll");
        self.define_hash(HashDef::LoadLibraryA, "LoadLibraryA");
        self.define_hash(
            HashDef::RtlAddVectoredExceptionHandler,
            "RtlAddVectoredExceptionHandler",
        );
        self.define_hash(HashDef::TlsAlloc, "TlsAlloc");
        self.define_hash(HashDef::RtlFlsAlloc, "RtlFlsAlloc");
        self.define_hash(HashDef::RtlFlsSetValue, "RtlFlsSetValue");
        self.define_hash(HashDef::GetProcessHeap, "GetProcessHeap");
        self.define_hash(HashDef::RtlAllocateHeap, "RtlAllocateHeap");
        self.define_hash(HashDef::RtlFreeHeap, "RtlFreeHeap");
        self.define_hash(
            HashDef::NtQuerySystemInformation,
            "NtQuerySystemInformation",
        );
        self.define_hash(
            HashDef::NtQueryInformationProcess,
            "NtQueryInformationProcess",
        );
        self.define_hash(HashDef::NtSetInformationThread, "NtSetInformationThread");
        self.define_hash(
            HashDef::NtQueryInformationThread,
            "NtQueryInformationThread",
        );
        self.define_hash(HashDef::MessageBoxA, "MessageBoxA");
        self.define_hash(HashDef::NtTerminateProcess, "NtTerminateProcess");
        #[cfg(debug_assertions)]
        self.define_hash(HashDef::AllocConsole, "AllocConsole");
        #[cfg(debug_assertions)]
        self.define_hash(HashDef::NtWriteFile, "NtWriteFile");

        let mut rng = rand::thread_rng();

        let mut data_tasks = Vec::new();

        for def in DataDef::VARIANTS {
            if *def == DataDef::VehStart || *def == DataDef::VehEnd {
                continue;
            }

            if self.data.contains_key(def) {
                data_tasks.push(EmissionTask::Data(*def));
            }
        }

        for def in BoolDef::VARIANTS {
            if self.bools.contains_key(def) {
                data_tasks.push(EmissionTask::Bool(*def));
            }
        }

        for def in StringDef::VARIANTS {
            if self.strings.contains_key(def) {
                data_tasks.push(EmissionTask::String(*def));
            }
        }

        for def in HashDef::VARIANTS {
            if self.hashes.contains_key(def) {
                data_tasks.push(EmissionTask::Hash(*def));
            }
        }

        data_tasks.shuffle(&mut rng);

        self.emit(&[
            EmissionTask::Function(FnDef::VmVehHandler, vm::functions::veh::handler),
            EmissionTask::Data(DataDef::VehStart),
        ]);

        let (data_phase_one, data_phase_two) = data_tasks.split_at(data_tasks.len() / 2);

        let mut phase_one = Vec::new();

        for (def, builder) in functions {
            phase_one.push(EmissionTask::Function(def, builder));
        }

        phase_one.extend(data_phase_one.iter().cloned());
        phase_one.shuffle(&mut rng);

        self.emit(&phase_one);

        let mut phase_two = Vec::new();

        for i in 0..self.dispatches.len() {
            phase_two.push(EmissionTask::DispatchTable(i));

            for j in 0..self.dispatches[i].stubs.len() {
                phase_two.push(EmissionTask::DispatchStub(i, j));
            }
        }

        phase_two.extend(data_phase_two.iter().cloned());
        phase_two.shuffle(&mut rng);

        self.emit(&phase_two);

        self.emit(&[EmissionTask::Data(DataDef::VehEnd)]);

        let result = self
            .asm
            .assemble_options(ip, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
            .unwrap();

        let labels = self
            .function_labels
            .values()
            .chain(self.data_labels.values())
            .chain(self.bool_labels.values())
            .chain(self.string_labels.values());

        for label in labels {
            if let Ok(rva) = result.label_ip(label) {
                self.addresses.insert(*label, rva);
            }
        }

        let offsets = &result.inner.new_instruction_offsets;

        for (def, (_, end)) in &self.functions {
            let label = self.function_labels[def];
            let start = result.label_ip(&label).unwrap();
            let offset = offsets[end - 1] as u64;
            let size = self.asm.instructions()[end - 1].len() as u64;
            self.sizes.insert(label, ip + offset + size - start);
        }

        let mut code = result.inner.code_buffer.clone();

        for dispatch in &self.dispatches {
            let rva = result.label_ip(&dispatch.table).unwrap();
            let offset = (rva - ip) as usize;

            for (index, stub, _) in &dispatch.stubs {
                let displacement = result.label_ip(stub).unwrap() as i64 - rva as i64;
                let slot = offset + *index as usize * size_of::<i64>();
                code[slot..slot + size_of::<i64>()].copy_from_slice(&displacement.to_le_bytes());
            }
        }

        let offset = (result
            .label_ip(self.data_labels.get(&DataDef::Functions).unwrap())
            .unwrap()
            - ip) as usize;

        for (i, def) in FnDef::VARIANTS.iter().enumerate() {
            let entry = offset + i * size_of::<u64>();

            let rva = self.addresses[&self.function_labels[def]] as u32;
            let size = self.sizes[&self.function_labels[def]] as u32;

            code[entry..entry + size_of::<u32>()].copy_from_slice(&rva.to_le_bytes());
            code[entry + size_of::<u32>()..entry + size_of::<u64>()]
                .copy_from_slice(&size.to_le_bytes());
        }

        code
    }
}
