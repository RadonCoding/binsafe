#![cfg(test)]

use std::{ffi::c_void, mem, ptr, sync::OnceLock};

use iced_x86::code_asm::{ecx, esi, ptr, rax, rcx, rdi, rdx, rsi};
use obfuscator::protections::virtualization::crypt;
use runtime::{
    mapper::Mappable,
    runtime::{DataDef, FnDef, Runtime},
    vm::{self, bytecode::VMReg},
};
use windows::Win32::System::{
    Memory::{
        VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    },
    Threading::{FlsAlloc, TlsAlloc},
};

mod instructions;
mod permutation;

pub(crate) struct Executor {
    pub rt: Runtime,
    pub mem: *mut c_void,
}

static TLS_STATE: OnceLock<u32> = OnceLock::new();
static TLS_KEY: OnceLock<u32> = OnceLock::new();
static FLS_CLEANUP: OnceLock<u32> = OnceLock::new();

fn initialize_tls() -> [(DataDef, u32); 3] {
    [
        (
            DataDef::VmStateTlsIndex,
            *TLS_STATE.get_or_init(|| unsafe { TlsAlloc() }),
        ),
        (
            DataDef::VmKeyTlsIndex,
            *TLS_KEY.get_or_init(|| unsafe { TlsAlloc() }),
        ),
        (
            DataDef::VmCleanupFlsIndex,
            *FLS_CLEANUP.get_or_init(|| unsafe { FlsAlloc(None) }),
        ),
    ]
}

impl Executor {
    pub const TEST_KEY_SEED: u64 = 0x1234567890ABCDEF;
    pub const TEST_KEY_MUL: u64 = 0x1234567890ABCDEF;
    pub const TEST_KEY_ADD: u64 = 0x1234567890ABCDEF;

    pub const SIZE: usize = 0x10000;

    pub fn new() -> Self {
        let mut rt = Runtime::new(64);

        rt.define_data_qword(DataDef::VmKeySeed, Self::TEST_KEY_SEED);
        rt.define_data_qword(DataDef::VmKeyMul, Self::TEST_KEY_MUL);
        rt.define_data_qword(DataDef::VmKeyAdd, Self::TEST_KEY_ADD);

        let mem = unsafe {
            VirtualAlloc(
                None,
                Self::SIZE,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };

        Self { rt, mem }
    }

    pub fn run(&mut self, setup: &[(VMReg, u64)], bytecode: &[u8]) -> [u64; VMReg::COUNT] {
        let dispatch = self.rt.func_labels[&FnDef::VmDispatch];

        // call ...
        self.rt
            .asm
            .call(self.rt.func_labels[&FnDef::VmTInit])
            .unwrap();

        // call ...
        self.rt
            .asm
            .call(self.rt.func_labels[&FnDef::VmHandlersInitialize])
            .unwrap();

        // mov ecx, [...]
        self.rt
            .asm
            .mov(ecx, ptr(self.rt.data_labels[&DataDef::VmStateTlsIndex]))
            .unwrap();
        // mov rcx, [0x1480 + rcx*8]
        self.rt.asm.mov(rcx, ptr(0x1480 + rcx * 8).gs()).unwrap();

        for &(reg, val) in setup {
            // mov rax, ...
            self.rt.asm.mov(rax, val).unwrap();
            // mov [rcx + ...], rax
            self.rt
                .asm
                .mov(ptr(rcx + self.rt.mapper.index(reg) * 8), rax)
                .unwrap();
        }

        // lea rdx, [...]
        self.rt
            .asm
            .lea(rdx, ptr(self.rt.data_labels[&DataDef::VmCode]))
            .unwrap();
        // call ...
        vm::utils::stack::call(&mut self.rt, dispatch);

        let mut state = [0u64; VMReg::COUNT];

        // mov esi, [...]
        self.rt
            .asm
            .mov(esi, ptr(self.rt.data_labels[&DataDef::VmStateTlsIndex]))
            .unwrap();
        // mov rsi, [0x1480 + rsi*8]
        self.rt.asm.mov(rsi, ptr(0x1480 + rsi * 8).gs()).unwrap();
        // mov rdi, ...
        self.rt.asm.mov(rdi, state.as_mut_ptr() as u64).unwrap();
        // mov rcx, ...
        self.rt.asm.mov(rcx, VMReg::COUNT as u64).unwrap();
        // rep movsq
        self.rt.asm.rep().movsq().unwrap();

        // ret
        self.rt.asm.ret().unwrap();

        self.rt.define_data_bytes(DataDef::VmCode, bytecode);

        let ip = self.mem as u64;

        let mut code = self.rt.assemble(ip);

        for (def, value) in initialize_tls() {
            let offset = (self.rt.lookup(self.rt.data_labels[&def]) - ip) as usize;
            code[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }

        assert!(code.len() <= Self::SIZE);

        unsafe {
            ptr::copy_nonoverlapping(code.as_ptr(), self.mem as *mut u8, code.len());
        }

        let entry_point = unsafe { mem::transmute::<*mut c_void, extern "C" fn()>(self.mem) };

        entry_point();

        state
    }
}

impl Drop for Executor {
    fn drop(&mut self) {
        unsafe {
            let _ = VirtualFree(self.mem, 0, MEM_RELEASE);
        }
    }
}

pub(crate) fn encrypt(bytecode: &mut Vec<u8>) {
    crypt::encrypt(
        bytecode,
        Executor::TEST_KEY_SEED,
        Executor::TEST_KEY_MUL,
        Executor::TEST_KEY_ADD,
        0,
    );
}

pub(crate) fn decrypt(block: &mut Vec<u8>) {
    crypt::decrypt(
        block,
        Executor::TEST_KEY_SEED,
        Executor::TEST_KEY_MUL,
        Executor::TEST_KEY_ADD,
        0,
    )
}

macro_rules! instruction {
    (branch $code:ident, $target:expr) => {
        iced_x86::Instruction::with_branch(iced_x86::Code::$code, $target).unwrap()
    };
    ($code:ident, $a:expr) => {
        iced_x86::Instruction::with1(iced_x86::Code::$code, $a).unwrap()
    };
    ($code:ident, $a:expr, $b:expr) => {
        iced_x86::Instruction::with2(iced_x86::Code::$code, $a, $b).unwrap()
    };
}

pub(crate) use instruction;
