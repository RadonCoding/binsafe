use std::collections::HashMap;

use iced_x86::{
    code_asm::{CodeAssembler, CodeLabel},
    BlockEncoderOptions,
};
use rand::seq::SliceRandom;

use crate::{
    mapper::{Mappable, Mapper},
    vm::{
        self,
        bytecode::{VMOp, VMReg},
        stack::VSTACK_SIZE,
    },
};

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum FnDef {
    /* VM */
    VmEntry,
    VmCrypt,
    VmDispatch,
    /* VM UTILS */
    ComputeAddress,
    /* VM HANDLERS */
    VmHandlerPushImm,
    VmHandlerPushReg64,
    VmHandlerPopReg64,
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
    /* VM STACK */
    InitializeStack,
}

#[derive(PartialEq, Eq, Hash)]
pub enum DataDef {
    VmHandlers,
    VmLock,
    VmState,
    VmStackPointer,
    VmStackContent,
    VmTable,
    VmCode,
    VmKeySeed,
    VmKeyMul,
    VmKeyAdd,
}

pub struct Runtime {
    pub asm: CodeAssembler,
    pub func_labels: HashMap<FnDef, CodeLabel>,
    pub addresses: HashMap<CodeLabel, u64>,
    pub data_labels: HashMap<DataDef, CodeLabel>,
    pub mapper: Mapper,
}

impl Runtime {
    pub fn new(bitness: u32) -> Self {
        let mut asm = CodeAssembler::new(bitness).unwrap();

        let mut func_labels = HashMap::new();
        func_labels.insert(FnDef::VmEntry, asm.create_label());
        func_labels.insert(FnDef::VmCrypt, asm.create_label());
        func_labels.insert(FnDef::VmDispatch, asm.create_label());

        func_labels.insert(FnDef::ComputeAddress, asm.create_label());

        func_labels.insert(FnDef::VmHandlerPushImm, asm.create_label());
        func_labels.insert(FnDef::VmHandlerPushReg64, asm.create_label());
        func_labels.insert(FnDef::VmHandlerPopReg64, asm.create_label());
        func_labels.insert(FnDef::VmHandlerSetRegImm, asm.create_label());
        func_labels.insert(FnDef::VmHandlerSetRegReg, asm.create_label());
        func_labels.insert(FnDef::VmHandlerSetRegMem, asm.create_label());
        func_labels.insert(FnDef::VmHandlerSetMemImm, asm.create_label());
        func_labels.insert(FnDef::VmHandlerSetMemReg, asm.create_label());
        func_labels.insert(FnDef::VmHandlerAddSubRegImm, asm.create_label());
        func_labels.insert(FnDef::VmHandlerAddSubRegReg, asm.create_label());
        func_labels.insert(FnDef::VmHandlerAddSubRegMem, asm.create_label());
        func_labels.insert(FnDef::VmHandlerAddSubMemReg, asm.create_label());
        func_labels.insert(FnDef::VmHandlerAddSubMemImm, asm.create_label());
        func_labels.insert(FnDef::VmHandlerBranchImm, asm.create_label());
        func_labels.insert(FnDef::VmHandlerBranchReg, asm.create_label());
        func_labels.insert(FnDef::VmHandlerBranchMem, asm.create_label());
        func_labels.insert(FnDef::VmHandlerJcc, asm.create_label());
        func_labels.insert(FnDef::VmHandlerNop, asm.create_label());

        func_labels.insert(FnDef::VmArithmeticFlags, asm.create_label());
        func_labels.insert(FnDef::VmArithmeticAddSub8, asm.create_label());
        func_labels.insert(FnDef::VmArithmeticAddSub16, asm.create_label());
        func_labels.insert(FnDef::VmArithmeticAddSub32, asm.create_label());
        func_labels.insert(FnDef::VmArithmeticAddSub64, asm.create_label());

        func_labels.insert(FnDef::InitializeStack, asm.create_label());

        let mut data_labels = HashMap::new();
        data_labels.insert(DataDef::VmHandlers, asm.create_label());
        data_labels.insert(DataDef::VmState, asm.create_label());
        data_labels.insert(DataDef::VmLock, asm.create_label());
        data_labels.insert(DataDef::VmStackPointer, asm.create_label());
        data_labels.insert(DataDef::VmStackContent, asm.create_label());
        data_labels.insert(DataDef::VmTable, asm.create_label());
        data_labels.insert(DataDef::VmCode, asm.create_label());
        data_labels.insert(DataDef::VmKeySeed, asm.create_label());
        data_labels.insert(DataDef::VmKeyMul, asm.create_label());
        data_labels.insert(DataDef::VmKeyAdd, asm.create_label());

        Self {
            asm,
            func_labels,
            addresses: HashMap::new(),
            data_labels,
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

    pub fn lookup(&self, label: CodeLabel) -> u64 {
        self.addresses[&label]
    }

    pub fn define_func<F>(&mut self, def: FnDef, builder: F)
    where
        F: FnOnce(&mut Self),
    {
        self.set_func_label(def);
        builder(self);
    }

    pub fn define_data_byte(&mut self, def: DataDef, data: &[u8]) {
        self.set_data_label(def);
        self.asm.db(data).unwrap();
    }

    pub fn define_data_word(&mut self, def: DataDef, data: &[u16]) {
        self.set_data_label(def);
        self.asm.dw(data).unwrap();
    }

    pub fn define_data_dword(&mut self, def: DataDef, data: &[u32]) {
        self.set_data_label(def);
        self.asm.dd(data).unwrap();
    }

    pub fn define_data_qword(&mut self, def: DataDef, data: &[u64]) {
        self.set_data_label(def);
        self.asm.dq(data).unwrap();
    }

    pub fn assemble(&mut self, ip: u64) -> Vec<u8> {
        let mut fn_defs: Vec<(FnDef, fn(&mut Runtime))> = vec![
            (FnDef::VmEntry, vm::entry::build),
            (FnDef::VmCrypt, vm::crypt::build),
            (FnDef::VmDispatch, vm::dispatch::build),
            (FnDef::ComputeAddress, vm::utils::compute_address::build),
            (FnDef::VmHandlerPushImm, vm::handlers::pushimm::build),
            (FnDef::VmHandlerPushReg64, vm::handlers::pushreg64::build),
            (FnDef::VmHandlerPopReg64, vm::handlers::popreg64::build),
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
            (FnDef::InitializeStack, vm::stack::initialize),
        ];

        let mut data_defs = vec![
            (DataDef::VmHandlers, vec![0u8; VMOp::COUNT * 8]),
            (DataDef::VmStackPointer, 0u64.to_le_bytes().to_vec()),
            (DataDef::VmStackContent, vec![0u8; VSTACK_SIZE]),
            (DataDef::VmState, vec![0u8; VMReg::COUNT * 8]),
            (DataDef::VmLock, vec![0u8]),
        ];

        let mut rng = rand::thread_rng();
        fn_defs.shuffle(&mut rng);
        data_defs.shuffle(&mut rng);

        for (def, builder) in fn_defs {
            self.define_func(def, builder);
        }

        for (def, bytes) in data_defs {
            self.define_data_byte(def, &bytes);
        }

        let options = self
            .asm
            .assemble_options(ip, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
            .unwrap();

        for label in self.func_labels.values() {
            if let Ok(ip) = options.label_ip(label) {
                self.addresses.insert(*label, ip);
            }
        }

        for label in self.data_labels.values() {
            if let Ok(ip) = options.label_ip(label) {
                self.addresses.insert(*label, ip);
            }
        }

        options.inner.code_buffer
    }
}
