use std::collections::HashMap;

use iced_x86::code_asm::{
    ptr, r12, r13, r14, r8, rax, rcx, rdx, AsmRegister64, CodeAssembler, CodeLabel,
};

use crate::{
    functions,
    vm::{
        self,
        bytecode::{VMReg, VM_OP_COUNT},
    },
};

#[derive(PartialEq, Eq, Hash)]
pub enum FnDef {
    /* VM */
    VmInitialize,
    VmEntryPoint,
    VmSearch,
    VmDispatcher,
    /* UTILS */
    ComputeEffectiveAddress,
    /* HANDLERS */
    VmHandlerSetRegImm,
    VmHandlerSetRegReg,
    VmHandlerSetRegMem,
    VmHandlerCallRel,
    VmHandlerCallReg,
    VmHandlerCallMem,
    /* CORE */
    ExceptionHandler,
    CompareUnicodeToAnsi,
    CompareAnsi,
    GetProcAddress,
}

#[derive(PartialEq, Eq, Hash)]
pub enum DataDef {
    BYTECODE,
    HANDLERS,
    NTDLL,
    RAVEH,
}

pub struct Runtime<'a> {
    pub asm: &'a mut CodeAssembler,
    pub func_labels: HashMap<FnDef, CodeLabel>,
    pub data_labels: HashMap<DataDef, CodeLabel>,
}

impl<'a> Runtime<'a> {
    pub fn new(asm: &'a mut CodeAssembler) -> Self {
        let mut func_labels = HashMap::new();
        func_labels.insert(FnDef::VmInitialize, asm.create_label());
        func_labels.insert(FnDef::VmEntryPoint, asm.create_label());
        func_labels.insert(FnDef::VmSearch, asm.create_label());
        func_labels.insert(FnDef::VmDispatcher, asm.create_label());

        func_labels.insert(FnDef::ComputeEffectiveAddress, asm.create_label());

        func_labels.insert(FnDef::VmHandlerSetRegImm, asm.create_label());
        func_labels.insert(FnDef::VmHandlerSetRegReg, asm.create_label());
        func_labels.insert(FnDef::VmHandlerSetRegMem, asm.create_label());
        func_labels.insert(FnDef::VmHandlerCallRel, asm.create_label());
        func_labels.insert(FnDef::VmHandlerCallReg, asm.create_label());
        func_labels.insert(FnDef::VmHandlerCallMem, asm.create_label());

        func_labels.insert(FnDef::ExceptionHandler, asm.create_label());
        func_labels.insert(FnDef::CompareUnicodeToAnsi, asm.create_label());
        func_labels.insert(FnDef::CompareAnsi, asm.create_label());
        func_labels.insert(FnDef::GetProcAddress, asm.create_label());

        let mut data_labels = HashMap::new();
        data_labels.insert(DataDef::BYTECODE, asm.create_label());
        data_labels.insert(DataDef::HANDLERS, asm.create_label());
        data_labels.insert(DataDef::NTDLL, asm.create_label());
        data_labels.insert(DataDef::RAVEH, asm.create_label());

        Self {
            asm,
            func_labels,
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

    fn build_initilization(&mut self, oep: Option<u32>) {
        // call ...
        self.asm
            .call(self.func_labels[&FnDef::VmInitialize])
            .unwrap();

        // lea rcx, [...]
        self.asm
            .lea(rcx, ptr(self.data_labels[&DataDef::NTDLL]))
            .unwrap();
        // lea rcx, [...]
        self.asm
            .lea(rdx, ptr(self.data_labels[&DataDef::RAVEH]))
            .unwrap();
        // call ...
        self.asm
            .call(self.func_labels[&FnDef::GetProcAddress])
            .unwrap();

        // mov rcx, 0x1
        self.asm.mov(rcx, 0x1u64).unwrap();
        // lea rdx, ...
        self.asm
            .lea(rdx, ptr(self.func_labels[&FnDef::ExceptionHandler]))
            .unwrap();
        // call rax
        self.asm.call(rax).unwrap();

        if let Some(oep) = oep {
            self.asm.jmp(oep as u64).unwrap();
        }
    }

    pub fn build_callbacks(&mut self, callbacks: &[u32]) {
        // push r12
        self.asm.push(r12).unwrap();
        // push r13
        self.asm.push(r13).unwrap();
        // push r14
        self.asm.push(r14).unwrap();

        // mov r12, rcx
        self.asm.mov(r12, rcx).unwrap();
        // mov r13, rdx
        self.asm.mov(r13, rdx).unwrap();
        // mov r14, r8
        self.asm.mov(r14, r8).unwrap();

        self.build_initilization(None);

        for &callback in callbacks {
            // mov rcx, r12
            self.asm.mov(rcx, r12).unwrap();
            // mov rdx, r13
            self.asm.mov(rdx, r13).unwrap();
            // mov r8, r14
            self.asm.mov(r8, r14).unwrap();
            // call ...
            self.asm.call(callback as u64).unwrap();
        }

        // pop r14
        self.asm.pop(r14).unwrap();
        // pop r13
        self.asm.pop(r13).unwrap();
        // pop r12
        self.asm.pop(r12).unwrap();

        // ret
        self.asm.ret().unwrap();
    }

    pub fn build_entry_point(&mut self, oep: u32) {
        self.build_initilization(Some(oep));
    }

    pub fn push_reg64(&mut self, reg: AsmRegister64) {
        self.asm
            .mov(rax, ptr(rcx + (VMReg::Rsp as u8 - 1) * 8))
            .unwrap();
        self.asm.sub(rax, 0x8).unwrap();
        self.asm
            .mov(ptr(rcx + (VMReg::Rsp as u8 - 1) * 8), rax)
            .unwrap();
        self.asm.mov(ptr(rax), reg).unwrap();
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
        self.define_func(FnDef::VmInitialize, vm::initialize::build);
        self.define_func(FnDef::VmEntryPoint, vm::entry_point::build);
        self.define_func(FnDef::VmSearch, vm::search::build);
        self.define_func(FnDef::VmDispatcher, vm::dispatcher::build);

        self.define_func(
            FnDef::ComputeEffectiveAddress,
            vm::utils::compute_effective_address::build,
        );

        self.define_func(FnDef::VmHandlerSetRegImm, vm::handlers::setregimm::build);
        self.define_func(FnDef::VmHandlerSetRegReg, vm::handlers::setregreg::build);
        self.define_func(FnDef::VmHandlerSetRegMem, vm::handlers::setregmem::build);
        self.define_func(FnDef::VmHandlerCallRel, vm::handlers::callrel::build);
        self.define_func(FnDef::VmHandlerCallReg, vm::handlers::callreg::build);
        self.define_func(FnDef::VmHandlerCallMem, vm::handlers::callmem::build);

        self.define_func(FnDef::ExceptionHandler, functions::exception_handler::build);
        self.define_func(
            FnDef::CompareUnicodeToAnsi,
            functions::compare_unicode_to_ansi::build,
        );
        self.define_func(FnDef::CompareAnsi, functions::compare_ansi::build);
        self.define_func(FnDef::GetProcAddress, functions::get_proc_address::build);

        self.define_data(DataDef::HANDLERS, &[0u8; VM_OP_COUNT * 8]);

        self.define_data(DataDef::NTDLL, b"ntdll.dll\0");
        self.define_data(DataDef::RAVEH, b"RtlAddVectoredExceptionHandler\0");

        self.asm.assemble(ip).unwrap()
    }
}
