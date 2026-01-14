use std::collections::HashMap;

use iced_x86::{
    code_asm::{ptr, rcx, rdx, CodeAssembler, CodeLabel},
    BlockEncoderOptions, Decoder, DecoderOptions, Encoder,
};
use rand::seq::SliceRandom;

use crate::{
    functions,
    mapper::{Mappable, Mapper},
    vm::{
        self,
        bytecode::{VMOp, VMReg},
    },
};
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[derive(Copy, Clone, PartialEq, Eq, Hash, EnumIter)]
pub enum FnDef {
    /* VM */
    VmGInit,
    VmTInit,
    VmEntry,
    VmExit,
    VmCrypt,
    VmDispatch,
    VmCleanup,
    /* VM UTILS */
    ComputeAddress,
    /* VM HANDLERS */
    VmHandlersInitialize,
    VmHandlerPushPopRegs,
    VmHandlerPushImm,
    VmHandlerPushReg,
    VmHandlerPopReg,
    VmHandlerSetRegImm,
    VmHandlerSetRegReg,
    VmHandlerSetRegMem,
    VmHandlerSetMemImm,
    VmHandlerSetMemReg,
    VmHandlerAddSubRegImm,
    VmHandlerAddSubRegMem,
    VmHandlerAddSubRegReg,
    VmHandlerAddSubMemImm,
    VmHandlerAddSubMemReg,
    VmHandlerBranchImm,
    VmHandlerBranchReg,
    VmHandlerBranchMem,
    VmHandlerJcc,
    VmHandlerNop,
    /* VM ARITHMETIC */
    VmArithmeticFlags,
    VmArithmeticAddSub8,
    VmArithmeticAddSub16,
    VmArithmeticAddSub32,
    VmArithmeticAddSub64,
    /* VM VEH */
    VmVehInitialize,
    VmVehHandler,
    /* CORE */
    CompareUnicodeToAnsi,
    CompareAnsi,
    GetProcAddress,
    #[cfg(debug_assertions)]
    Strlen,
    #[cfg(debug_assertions)]
    Print,
    #[cfg(debug_assertions)]
    Fmtdec,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, EnumIter)]
pub enum DataDef {
    VehStart,
    VmHandlers,
    VmGlobalState,
    VmStateTlsIndex,
    VmStackTlsIndex,
    VmCleanupFlsIndex,
    VmTable,
    VmCode,
    VmKeySeed,
    VmKeyMul,
    VmKeyAdd,
    VehEnd,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, EnumIter)]
pub enum BoolDef {
    VmIsLocked,
    VmHasVeh,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash, EnumIter)]
pub enum StringDef {
    Ntdll,
    KERNEL32,
    KERNELBASE,
    NtQueryInformationProcess,
    RtlAddVectoredExceptionHandler,
    TlsAlloc,
    RtlFlsAlloc,
    RtlFlsSetValue,
    GetProcessHeap,
    RtlAllocateHeap,
    RtlFreeHeap,
    NtWriteFile,
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
    string_labels: HashMap<StringDef, CodeLabel>,
    strings: HashMap<StringDef, Vec<u8>>,
    addresses: HashMap<CodeLabel, u64>,
    fixups: HashMap<CodeLabel, (CodeLabel, u64, Option<usize>)>,
    current_chain: Option<usize>,
    next_chain_id: usize,
    pub mapper: Mapper,
}

impl Runtime {
    pub fn new(bitness: u32) -> Self {
        let mut asm = CodeAssembler::new(bitness).unwrap();

        let mut func_labels = HashMap::new();

        for def in FnDef::iter() {
            func_labels.insert(def, asm.create_label());
        }

        let mut data_labels = HashMap::new();

        for def in DataDef::iter() {
            data_labels.insert(def, asm.create_label());
        }

        let mut bool_labels = HashMap::new();

        for def in BoolDef::iter() {
            bool_labels.insert(def, asm.create_label());
        }

        let mut string_labels = HashMap::new();

        for def in StringDef::iter() {
            string_labels.insert(def, asm.create_label());
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
            addresses: HashMap::new(),
            fixups: HashMap::new(),
            mapper: Mapper::new(),
            current_chain: None,
            next_chain_id: 0,
        }
    }

    pub fn with_chain<F>(&mut self, f: F)
    where
        F: FnOnce(&mut Self),
    {
        self.current_chain = Some(self.next_chain_id);
        self.next_chain_id += 1;

        f(self);

        self.current_chain = None;
    }

    pub fn mark_as_encrypted(&mut self, target: CodeLabel) -> u64 {
        let mut label = self.asm.create_label();
        self.asm.set_label(&mut label).unwrap();
        let key = rand::random::<u64>();
        self.fixups.insert(label, (target, key, self.current_chain));
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

    pub fn get_proc_address(&mut self, module_name: StringDef, export_name: StringDef) {
        // lea rcx, [...]
        self.asm
            .lea(rcx, ptr(self.string_labels[&module_name]))
            .unwrap();
        // lea rdx, [...]
        self.asm
            .lea(rdx, ptr(self.string_labels[&export_name]))
            .unwrap();
        // call ...
        self.asm
            .call(self.func_labels[&FnDef::GetProcAddress])
            .unwrap();
    }

    pub fn assemble(&mut self, ip: u64) -> Vec<u8> {
        let mut shuffled = Vec::new();

        let functions: Vec<(FnDef, fn(&mut Runtime))> = vec![
            (FnDef::VmGInit, vm::ginit::build),
            (FnDef::VmTInit, vm::tinit::build),
            (FnDef::VmEntry, vm::entry::build),
            (FnDef::VmExit, vm::exit::build),
            (FnDef::VmCrypt, vm::crypt::build),
            (FnDef::VmDispatch, vm::dispatch::build),
            (FnDef::VmCleanup, vm::cleanup::build),
            (FnDef::ComputeAddress, vm::utils::compute_address::build),
            (FnDef::VmHandlersInitialize, vm::handlers::initialize),
            (
                FnDef::VmHandlerPushPopRegs,
                vm::handlers::pushpopregs::build,
            ),
            (FnDef::VmHandlerPushImm, vm::handlers::pushimm::build),
            (FnDef::VmHandlerPushReg, vm::handlers::pushreg::build),
            (FnDef::VmHandlerPopReg, vm::handlers::popreg::build),
            (FnDef::VmHandlerSetRegImm, vm::handlers::setregimm::build),
            (FnDef::VmHandlerSetRegReg, vm::handlers::setregreg::build),
            (FnDef::VmHandlerSetRegMem, vm::handlers::setregmem::build),
            (FnDef::VmHandlerSetMemImm, vm::handlers::setmemimm::build),
            (FnDef::VmHandlerSetMemReg, vm::handlers::setmemreg::build),
            (
                FnDef::VmHandlerAddSubRegImm,
                vm::handlers::arithmetic::addsubregimm::build,
            ),
            (
                FnDef::VmHandlerAddSubRegMem,
                vm::handlers::arithmetic::addsubregmem::build,
            ),
            (
                FnDef::VmHandlerAddSubRegReg,
                vm::handlers::arithmetic::addsubregreg::build,
            ),
            (
                FnDef::VmHandlerAddSubMemImm,
                vm::handlers::arithmetic::addsubmemimm::build,
            ),
            (
                FnDef::VmHandlerAddSubMemReg,
                vm::handlers::arithmetic::addsubmemreg::build,
            ),
            (FnDef::VmHandlerBranchImm, vm::handlers::branchimm::build),
            (FnDef::VmHandlerBranchReg, vm::handlers::branchreg::build),
            (FnDef::VmHandlerBranchMem, vm::handlers::branchmem::build),
            (FnDef::VmHandlerJcc, vm::handlers::jcc::build),
            (FnDef::VmHandlerNop, vm::handlers::nop::build),
            (
                FnDef::VmArithmeticFlags,
                vm::handlers::arithmetic::flags::build,
            ),
            (
                FnDef::VmArithmeticAddSub8,
                vm::handlers::arithmetic::addsub8::build,
            ),
            (
                FnDef::VmArithmeticAddSub16,
                vm::handlers::arithmetic::addsub16::build,
            ),
            (
                FnDef::VmArithmeticAddSub32,
                vm::handlers::arithmetic::addsub32::build,
            ),
            (
                FnDef::VmArithmeticAddSub64,
                vm::handlers::arithmetic::addsub64::build,
            ),
            (FnDef::VmVehInitialize, vm::veh::initialize),
            (
                FnDef::CompareUnicodeToAnsi,
                functions::compare_unicode_to_ansi::build,
            ),
            (FnDef::CompareAnsi, functions::compare_ansi::build),
            (FnDef::GetProcAddress, functions::get_proc_address::build),
            #[cfg(debug_assertions)]
            (FnDef::Strlen, functions::strlen::build),
            #[cfg(debug_assertions)]
            (FnDef::Print, functions::print::build),
            #[cfg(debug_assertions)]
            (FnDef::Fmtdec, functions::fmtdec::build),
        ];

        self.define_data_byte(DataDef::VehStart, 0x0);
        self.define_data_byte(DataDef::VehEnd, 0x0);

        self.define_data_bytes(DataDef::VmHandlers, &[0u8; VMOp::COUNT * 8]);
        self.define_data_bytes(DataDef::VmGlobalState, &[0u8; VMReg::COUNT * 8]);

        self.define_data_dword(DataDef::VmStateTlsIndex, 0);
        self.define_data_dword(DataDef::VmStackTlsIndex, 0);
        self.define_data_dword(DataDef::VmCleanupFlsIndex, 0);

        self.define_bool(BoolDef::VmIsLocked, false);
        self.define_bool(BoolDef::VmHasVeh, false);

        self.define_string(StringDef::Ntdll, "ntdll.dll");
        self.define_string(StringDef::KERNEL32, "KERNEL32.DLL");
        self.define_string(StringDef::KERNELBASE, "KERNELBASE.DLL");
        self.define_string(
            StringDef::NtQueryInformationProcess,
            "NtQueryInformationProcess",
        );
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
        #[cfg(debug_assertions)]
        self.define_string(StringDef::NtWriteFile, "NtWriteFile");

        for (def, builder) in functions {
            shuffled.push(EmissionTask::Function(def, builder));
        }

        for def in DataDef::iter() {
            if def == DataDef::VehStart || def == DataDef::VehEnd {
                continue;
            }

            if self.data.contains_key(&def) {
                shuffled.push(EmissionTask::Data(def));
            }
        }

        for def in BoolDef::iter() {
            if self.bools.contains_key(&def) {
                shuffled.push(EmissionTask::Bool(def));
            }
        }

        for def in StringDef::iter() {
            if self.strings.contains_key(&def) {
                shuffled.push(EmissionTask::String(def));
            }
        }

        let mut rng = rand::thread_rng();
        shuffled.shuffle(&mut rng);

        let mut tasks = Vec::new();
        tasks.push(EmissionTask::Function(
            FnDef::VmVehHandler,
            vm::veh::handler,
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
                    self.asm.db(&self.data[&def]).unwrap();
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
