use std::collections::HashMap;

use iced_x86::{
    code_asm::{ptr, r10, r11, rcx, AsmRegister64, CodeLabel},
    BlockEncoderOptions,
};
use rand::seq::SliceRandom;

use crate::{
    assembler::Assembler,
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
        VmRegistersCopy,
        VmVectorsCapture,
        VmVectorsRestore,
        VmVectorsCopy,
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
        VmHandlerTest,
        VmHandlerRol,
        VmHandlerRor,
        VmHandlerShl,
        VmHandlerShr,
        VmHandlerSar,
        VmHandlerMul,
        VmHandlerTrailingZeros,
        VmHandlerBitScanReverse,
        VmHandlerByteSwap,
        VmHandlerBitTest,
        VmHandlerBitTestSet,
        VmHandlerBitTestReset,
        VmHandlerBitTestComplement,
        VmHandlerAddCarry,
        VmHandlerSubBorrow,
        VmHandlerExchange,
        VmHandlerExchangeAdd,
        VmHandlerCompareExchange,
        VmHandlerPush,
        VmHandlerPop,
        VmHandlerDiscard,
        VmHandlerPackedByteMask,
        VmHandlerPackedByteEqual,
        VmHandlerVectorAnd,
        VmHandlerVectorOr,
        VmHandlerVectorXor,
        VmHandlerVectorAndNot,
        VmHandlerDivide,
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
        Format,
    }
}

mapped! {
    DataDef {
        Functions,
        VehStart,
        VmGlobalRegisters,
        VmGlobalVectors,
        VmRegistersTlsIndex,
        VmKeyTlsIndex,
        VmCleanupFlsIndex,
        VmTable,
        VmCode,
        VmTrampolines,
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
        AllocConsole,
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
        AllocConsole,
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
            ImportDef::AllocConsole { .. } => (StringDef::KERNELBASE, StringDef::AllocConsole),
            #[cfg(debug_assertions)]
            ImportDef::NtWriteFile { .. } => (StringDef::Ntdll, StringDef::NtWriteFile),
        }
    }
}

#[derive(Clone, Copy)]
enum EmissionTask {
    Function(FnDef, fn(&mut Runtime)),
    Data(DataDef),
    Bool(BoolDef),
    String(StringDef),
    Dispatch(usize),
}

struct Dispatch {
    table: CodeLabel,
    fallback: CodeLabel,
    stubs: Vec<(u8, CodeLabel)>,
}

impl Dispatch {
    fn slots(&self) -> usize {
        self.stubs
            .iter()
            .map(|(i, _)| *i as usize)
            .max()
            .map(|m| m + 1)
            .unwrap_or(0)
    }
}

pub struct Runtime {
    pub asm: Assembler,

    pub function_labels: HashMap<FnDef, CodeLabel>,
    pub data_labels: HashMap<DataDef, CodeLabel>,
    pub bool_labels: HashMap<BoolDef, CodeLabel>,
    pub string_labels: HashMap<StringDef, CodeLabel>,

    data: HashMap<DataDef, Vec<u8>>,
    bools: HashMap<BoolDef, bool>,
    strings: HashMap<StringDef, Vec<u8>>,

    imports: HashMap<ImportDef, usize>,

    dispatches: Vec<Dispatch>,

    addresses: HashMap<CodeLabel, u64>,

    pub mapper: Mapper,
}

impl Runtime {
    pub fn new(bitness: u32) -> Self {
        let mut asm = Assembler::new(bitness).unwrap();

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

        let mut imports = HashMap::new();

        for (i, def) in ImportDef::VARIANTS.iter().enumerate() {
            imports.insert(*def, i);
        }

        Self {
            asm,

            function_labels,
            data_labels,
            bool_labels,
            string_labels,

            data: HashMap::new(),
            bools: HashMap::new(),
            strings: HashMap::new(),

            imports,

            dispatches: Vec::new(),

            addresses: HashMap::new(),

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

        let mut fallback = self.asm.create_label();

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
            let mut stub = self.asm.create_label();

            self.asm.set_label(&mut stub).unwrap();
            {
                // lea r10, [...]
                self.asm.lea(r10, ptr(target)).unwrap();
                // sub r10, r11
                self.asm.sub(r10, r11).unwrap();
                // mov [r11 + ...], r10
                self.asm.mov(ptr(r11 + index as i32 * 8), r10).unwrap();
                // add r10, r11
                self.asm.add(r10, r11).unwrap();

                // jmp r10
                self.asm.jmp(r10).unwrap();
            }

            stubs.push((index, stub));
        }

        self.asm.set_label(&mut fallback).unwrap();
        self.asm.zero_bytes().unwrap();

        self.dispatches.push(Dispatch {
            table,
            fallback,
            stubs,
        });
    }

    fn emit(&mut self, tasks: &[EmissionTask]) {
        for &task in tasks {
            match task {
                EmissionTask::Function(def, builder) => {
                    self.set_function_label(def);
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
                EmissionTask::Dispatch(index) => {
                    let dispatch = &mut self.dispatches[index];

                    self.asm.set_label(&mut dispatch.table).unwrap();

                    for _ in 0..dispatch.slots() {
                        self.asm.dq(&[0u64]).unwrap();
                    }
                }
            }
        }
    }

    pub fn assemble(&mut self, ip: u64) -> Vec<u8> {
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
            (FnDef::VmRegistersCopy, vm::functions::registers::copy),
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
            (FnDef::VmHandlerTest, vm::handlers::test::build),
            (FnDef::VmHandlerRol, vm::handlers::rol::build),
            (FnDef::VmHandlerRor, vm::handlers::ror::build),
            (FnDef::VmHandlerShl, vm::handlers::shl::build),
            (FnDef::VmHandlerShr, vm::handlers::shr::build),
            (FnDef::VmHandlerSar, vm::handlers::sar::build),
            (FnDef::VmHandlerMul, vm::handlers::mul::build),
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
            (FnDef::VmHandlerAddCarry, vm::handlers::add_carry::build),
            (FnDef::VmHandlerSubBorrow, vm::handlers::sub_borrow::build),
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
            (FnDef::VmHandlerVectorOr, vm::handlers::vector_or::build),
            (FnDef::VmHandlerVectorXor, vm::handlers::vector_xor::build),
            (
                FnDef::VmHandlerVectorAndNot,
                vm::handlers::vector_and_not::build,
            ),
            (FnDef::VmHandlerDivide, vm::handlers::divide::build),
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
            (FnDef::Format, functions::format::build),
        ];

        self.define_data_byte(DataDef::VehStart, 0x0);
        self.define_data_byte(DataDef::VehEnd, 0x0);

        self.define_data_bytes(DataDef::Functions, &vec![0u8; FnDef::COUNT * 8]);
        self.define_data_bytes(DataDef::VmGlobalRegisters, &[0u8; VMReg::COUNT * 8]);
        self.define_data_bytes(DataDef::VmGlobalVectors, &[0u8; VMVec::COUNT * 32]);

        self.define_data_dword(DataDef::VmRegistersTlsIndex, 0);
        self.define_data_dword(DataDef::VmKeyTlsIndex, 0);
        self.define_data_dword(DataDef::VmCleanupFlsIndex, 0);

        self.define_data_bytes(DataDef::ImportAddresses, &vec![0u8; self.imports.len() * 8]);
        self.define_data_bytes(DataDef::ImportNames, &vec![0u8; self.imports.len() * 16]);

        self.define_bool(BoolDef::VmIsLocked, false);
        self.define_bool(BoolDef::VmHasVeh, false);

        self.define_string(StringDef::Ntdll, "ntdll.dll");
        self.define_string(StringDef::KERNEL32, "KERNEL32.DLL");
        self.define_string(StringDef::KERNELBASE, "KERNELBASE.dll");
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
        self.define_string(StringDef::AllocConsole, "AllocConsole");
        #[cfg(debug_assertions)]
        self.define_string(StringDef::NtWriteFile, "NtWriteFile");

        let mut rng = rand::thread_rng();

        let mut data_tasks = Vec::new();

        for def in DataDef::VARIANTS {
            if *def == DataDef::Functions || *def == DataDef::VehStart || *def == DataDef::VehEnd {
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

        data_tasks.shuffle(&mut rng);

        self.emit(&[
            EmissionTask::Data(DataDef::Functions),
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
            phase_two.push(EmissionTask::Dispatch(i));
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

        let mut code = result.inner.code_buffer.clone();

        for dispatch in &self.dispatches {
            let table = (result.label_ip(&dispatch.table).unwrap() - ip) as usize;
            let fallback = result.label_ip(&dispatch.fallback).unwrap() as i64;

            let base = result.label_ip(&dispatch.table).unwrap() as i64;

            for i in 0..dispatch.slots() {
                let displacement = fallback - base;
                code[table + i * 8..table + i * 8 + 8].copy_from_slice(&displacement.to_le_bytes());
            }

            for (index, stub) in &dispatch.stubs {
                let stub = result.label_ip(stub).unwrap() as i64;
                let slot = table + *index as usize * 8;
                let displacement = stub - base;
                code[slot..slot + 8].copy_from_slice(&displacement.to_le_bytes());
            }
        }

        let functions = (result
            .label_ip(&self.data_labels[&DataDef::Functions])
            .unwrap()
            - ip) as usize;

        for def in FnDef::VARIANTS {
            if let Ok(address) = result.label_ip(&self.function_labels[def]) {
                let slot = functions + self.mapper.index(*def) as usize * 8;
                code[slot..slot + 8].copy_from_slice(&address.to_le_bytes());
            }
        }

        code
    }
}
