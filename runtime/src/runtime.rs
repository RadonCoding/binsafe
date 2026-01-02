use std::collections::HashMap;

use iced_x86::{
    code_asm::{CodeAssembler, CodeLabel},
    BlockEncoderOptions,
};

use crate::vm::{self, bytecode::VM_OP_COUNT, entry::VM_STATE_SIZE, stack::VM_STACK_SIZE};

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum FnDef {
    /* VM */
    VmEntry,
    VmDispatch,
    /* VM UTILS */
    ComputeAddress,
    /* VM HANDLERS */
    VmHandlerPushImm,
    VmHandlerPushReg64,
    VmHandlerSetRegImm,
    VmHandlerSetRegReg,
    VmHandlerSetRegMem,
    VmHandlerSetMemImm,
    VmHandlerSetMemReg,
    VmHandlerAddSubRegImm,
    VmHandlerAddSubRegReg,
    VmHandlerAddSubMemImm,
    VmHandlerBranchRel,
    VmHandlerBranchReg,
    VmHandlerBranchMem,
    VmHandlerJcc,
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
    VmState,
    VmStackPointer,
    VmStackContent,
    VmCode,
}

#[derive(PartialEq, Eq, Hash)]
pub enum ImportDef {}

pub struct Runtime {
    pub asm: CodeAssembler,
    pub func_labels: HashMap<FnDef, CodeLabel>,
    pub addresses: HashMap<CodeLabel, u64>,
    pub data_labels: HashMap<DataDef, CodeLabel>,
}

impl Runtime {
    pub fn new(bitness: u32) -> Self {
        let mut asm = CodeAssembler::new(bitness).unwrap();

        let mut func_labels = HashMap::new();
        func_labels.insert(FnDef::VmEntry, asm.create_label());
        func_labels.insert(FnDef::VmDispatch, asm.create_label());

        func_labels.insert(FnDef::ComputeAddress, asm.create_label());

        func_labels.insert(FnDef::VmHandlerPushImm, asm.create_label());
        func_labels.insert(FnDef::VmHandlerPushReg64, asm.create_label());
        func_labels.insert(FnDef::VmHandlerSetRegImm, asm.create_label());
        func_labels.insert(FnDef::VmHandlerSetRegReg, asm.create_label());
        func_labels.insert(FnDef::VmHandlerSetRegMem, asm.create_label());
        func_labels.insert(FnDef::VmHandlerSetMemImm, asm.create_label());
        func_labels.insert(FnDef::VmHandlerSetMemReg, asm.create_label());
        func_labels.insert(FnDef::VmHandlerAddSubRegImm, asm.create_label());
        func_labels.insert(FnDef::VmHandlerAddSubRegReg, asm.create_label());
        func_labels.insert(FnDef::VmHandlerAddSubMemImm, asm.create_label());
        func_labels.insert(FnDef::VmHandlerBranchRel, asm.create_label());
        func_labels.insert(FnDef::VmHandlerBranchReg, asm.create_label());
        func_labels.insert(FnDef::VmHandlerBranchMem, asm.create_label());
        func_labels.insert(FnDef::VmHandlerJcc, asm.create_label());

        func_labels.insert(FnDef::VmArithmeticFlags, asm.create_label());
        func_labels.insert(FnDef::VmArithmeticAddSub8, asm.create_label());
        func_labels.insert(FnDef::VmArithmeticAddSub16, asm.create_label());
        func_labels.insert(FnDef::VmArithmeticAddSub32, asm.create_label());
        func_labels.insert(FnDef::VmArithmeticAddSub64, asm.create_label());

        func_labels.insert(FnDef::InitializeStack, asm.create_label());

        let mut data_labels = HashMap::new();
        data_labels.insert(DataDef::VmHandlers, asm.create_label());
        data_labels.insert(DataDef::VmState, asm.create_label());
        data_labels.insert(DataDef::VmStackPointer, asm.create_label());
        data_labels.insert(DataDef::VmStackContent, asm.create_label());
        data_labels.insert(DataDef::VmCode, asm.create_label());

        Self {
            asm,
            func_labels,
            addresses: HashMap::new(),
            data_labels,
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

    pub fn define_data(&mut self, def: DataDef, data: &[u8]) {
        self.set_data_label(def);
        self.asm.db(data).unwrap();
    }

    pub fn assemble(&mut self, ip: u64) -> Vec<u8> {
        self.define_func(FnDef::VmEntry, vm::entry::build);
        self.define_func(FnDef::VmDispatch, vm::dispatch::build);

        self.define_func(FnDef::ComputeAddress, vm::utils::compute_address::build);

        self.define_func(FnDef::VmHandlerPushImm, vm::handlers::pushimm::build);
        self.define_func(FnDef::VmHandlerPushReg64, vm::handlers::pushreg64::build);
        self.define_func(FnDef::VmHandlerSetRegImm, vm::handlers::setregimm::build);
        self.define_func(FnDef::VmHandlerSetRegReg, vm::handlers::setregreg::build);
        self.define_func(FnDef::VmHandlerSetRegMem, vm::handlers::setregmem::build);
        self.define_func(FnDef::VmHandlerSetMemImm, vm::handlers::setmemimm::build);
        self.define_func(FnDef::VmHandlerSetMemReg, vm::handlers::setmemreg::build);
        self.define_func(
            FnDef::VmHandlerAddSubRegImm,
            vm::handlers::arithmetic::addsubregimm::build,
        );
        self.define_func(
            FnDef::VmHandlerAddSubRegReg,
            vm::handlers::arithmetic::addsubregreg::build,
        );
        self.define_func(
            FnDef::VmHandlerAddSubMemImm,
            vm::handlers::arithmetic::addsubmemimm::build,
        );
        self.define_func(FnDef::VmHandlerBranchRel, vm::handlers::branchrel::build);
        self.define_func(FnDef::VmHandlerBranchReg, vm::handlers::branchreg::build);
        self.define_func(FnDef::VmHandlerBranchMem, vm::handlers::branchmem::build);
        self.define_func(FnDef::VmHandlerJcc, vm::handlers::jcc::build);

        self.define_func(
            FnDef::VmArithmeticFlags,
            vm::handlers::arithmetic::flags::build,
        );
        self.define_func(
            FnDef::VmArithmeticAddSub8,
            vm::handlers::arithmetic::addsub8::build,
        );
        self.define_func(
            FnDef::VmArithmeticAddSub16,
            vm::handlers::arithmetic::addsub16::build,
        );
        self.define_func(
            FnDef::VmArithmeticAddSub32,
            vm::handlers::arithmetic::addsub32::build,
        );
        self.define_func(
            FnDef::VmArithmeticAddSub64,
            vm::handlers::arithmetic::addsub64::build,
        );

        self.define_func(FnDef::InitializeStack, vm::stack::initialize);

        self.define_data(DataDef::VmHandlers, &[0u8; VM_OP_COUNT * 8]);

        self.define_data(DataDef::VmStackPointer, &[0u8; 8]);
        self.define_data(DataDef::VmStackContent, &[0u8; VM_STACK_SIZE]);

        self.define_data(DataDef::VmState, &[0u8; VM_STATE_SIZE]);

        let options = self
            .asm
            .assemble_options(ip, BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS)
            .unwrap();

        for label in self.func_labels.values() {
            match options.label_ip(label) {
                Ok(ip) => {
                    self.addresses.insert(*label, ip);
                }
                Err(_) => continue,
            }
        }

        for label in self.data_labels.values() {
            match options.label_ip(label) {
                Ok(ip) => {
                    self.addresses.insert(*label, ip);
                }
                Err(_) => continue,
            }
        }

        options.inner.code_buffer
    }
}
