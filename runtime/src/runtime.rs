use std::collections::HashMap;

use iced_x86::{
    code_asm::{ptr, rcx, rdx, CodeAssembler, CodeLabel},
    BlockEncoderOptions,
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
    /* VM STACK */
    VmStackInitialize,
    /* CORE */
    CompareUnicodeToAnsi,
    CompareAnsi,
    GetProcAddress,
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
    RtlAddVectoredExceptionHandler,
    TlsAlloc,
    RtlFlsAlloc,
    RtlFlsSetValue,
    GetProcessHeap,
    RtlAllocateHeap,
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
    pub addresses: HashMap<CodeLabel, u64>,
    pub data_labels: HashMap<DataDef, CodeLabel>,
    pub data: HashMap<DataDef, Vec<u8>>,
    pub bool_labels: HashMap<BoolDef, CodeLabel>,
    pub bools: HashMap<BoolDef, bool>,
    pub string_labels: HashMap<StringDef, CodeLabel>,
    pub strings: HashMap<StringDef, Vec<u8>>,
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
            addresses: HashMap::new(),
            data_labels,
            data: HashMap::new(),
            bool_labels,
            bools: HashMap::new(),
            string_labels,
            strings: HashMap::new(),
            mapper: Mapper::new(),
        }
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
            (FnDef::ComputeAddress, vm::utils::compute_address::build),
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
        ];

        self.define_data_byte(DataDef::VehStart, 0x90);
        self.define_data_byte(DataDef::VehEnd, 0x90);

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
            StringDef::RtlAddVectoredExceptionHandler,
            "RtlAddVectoredExceptionHandler",
        );
        self.define_string(StringDef::TlsAlloc, "TlsAlloc");
        self.define_string(StringDef::RtlFlsAlloc, "RtlFlsAlloc");
        self.define_string(StringDef::RtlFlsSetValue, "RtlFlsSetValue");
        self.define_string(StringDef::GetProcessHeap, "GetProcessHeap");
        self.define_string(StringDef::RtlAllocateHeap, "RtlAllocateHeap");

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

        let options = self
            .asm
            .assemble_options(ip, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
            .unwrap();

        for label in self
            .func_labels
            .values()
            .chain(self.data_labels.values())
            .chain(self.string_labels.values())
        {
            if let Ok(ip) = options.label_ip(label) {
                self.addresses.insert(*label, ip);
            }
        }

        options.inner.code_buffer
    }
}
