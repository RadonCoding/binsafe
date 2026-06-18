#![cfg(test)]

use std::{
    collections::{HashMap, HashSet},
    ffi::c_void,
    hint, mem, ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        LazyLock, Mutex, OnceLock,
    },
};

use crate::{
    constants::{FAKE_BRANCH_ADDRESS, REGISTERS, VECTORS},
    instrumentation::{
        initialize_context, native_handler, read_register, read_vectors, virtual_handler,
        write_register, write_vectors,
    },
};
use iced_x86::{
    code_asm::{ptr, r12, r12d, r8, r9, rax, rcx, ymm0},
    BlockEncoder, BlockEncoderOptions, Instruction, InstructionBlock,
};
use obfuscator::protections::virtualization::crypt;
use runtime::{
    mapper::Mappable,
    runtime::{BoolDef, DataDef, FnDef, Runtime},
    vm::bytecode::{VMFlag, VMReg, VMVec},
};
use windows::Win32::{
    Foundation::CloseHandle,
    System::{
        Diagnostics::Debug::{
            AddVectoredExceptionHandler, GetThreadContext, SetThreadContext, SetXStateFeaturesMask,
            CONTEXT, CONTEXT_ALL_AMD64, CONTEXT_XSTATE_AMD64,
        },
        Memory::{
            VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
            PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
        },
        Threading::{
            CreateThread, FlsAlloc, ResumeThread, SuspendThread, TlsAlloc, WaitForSingleObject,
            INFINITE, THREAD_CREATE_RUN_IMMEDIATELY, THREAD_CREATE_SUSPENDED,
        },
    },
};

mod constants;
mod emitter;
mod instructions;
mod instrumentation;
mod permutation;

static FAKE_BRANCH_MAPPED: OnceLock<()> = OnceLock::new();

static TLS_REGISTERS: OnceLock<u32> = OnceLock::new();
static TLS_KEY: OnceLock<u32> = OnceLock::new();
static TLS_DEBUG: OnceLock<u32> = OnceLock::new();
static FLS_CLEANUP: OnceLock<u32> = OnceLock::new();

static NATIVE_REGISTRY: LazyLock<Mutex<HashMap<u32, (usize, usize)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NATIVE_HANDLER: OnceLock<()> = OnceLock::new();

static VIRTUAL_REGISTRY: LazyLock<Mutex<HashSet<u32>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));
static VIRTUAL_HANDLER: OnceLock<()> = OnceLock::new();

const XSTATE_AVX: u32 = 2;
const XSTATE_MASK_AVX: u64 = 4;

#[derive(Clone, PartialEq, Eq, Default)]
pub(crate) struct State {
    pub registers: HashMap<VMReg, u64>,
    pub vectors: HashMap<VMVec, [u128; 2]>,
}

pub(crate) enum Difference {
    Register(VMReg, u64, u64),
    Vector(VMVec, [u128; 2], [u128; 2]),
}

impl State {
    pub fn with<T: Into<u64>>(mut self, register: VMReg, value: T) -> Self {
        self.registers.insert(register, value.into());
        self
    }

    pub fn zeroed(self, register: VMReg) -> Self {
        self.with(register, 0u64)
    }

    pub fn compare(&self, other: &Self) -> Vec<Difference> {
        let mut differences = Vec::new();
        for (&register, &expected) in &self.registers {
            if let Some(&received) = other.registers.get(&register) {
                if expected != received {
                    differences.push(Difference::Register(register, expected, received));
                }
            }
        }
        for (&vector, &expected) in &self.vectors {
            if let Some(&received) = other.vectors.get(&vector) {
                if expected != received {
                    differences.push(Difference::Vector(vector, expected, received));
                }
            }
        }
        differences
    }
}

pub(crate) struct Executor {
    pub rt: Runtime,
    pub mem: *mut c_void,
}

impl Executor {
    pub const TEST_KEY_SEED: u64 = 0x1234567890ABCDEF;
    pub const TEST_KEY_MUL: u64 = 0x1234567890ABCDEF;
    pub const TEST_KEY_ADD: u64 = 0x1234567890ABCDEF;

    pub const SIZE: usize = 0x10000;

    pub fn new() -> Self {
        FAKE_BRANCH_MAPPED.get_or_init(|| unsafe {
            let _ = VirtualAlloc(
                Some(FAKE_BRANCH_ADDRESS as *const c_void),
                Self::SIZE,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
        });

        let mut rt = Runtime::new(64);

        rt.define_data_qword(DataDef::VmKeySeed, Self::TEST_KEY_SEED);
        rt.define_data_qword(DataDef::VmKeyMul, Self::TEST_KEY_MUL);
        rt.define_data_qword(DataDef::VmKeyAdd, Self::TEST_KEY_ADD);

        rt.define_bool(BoolDef::VmHasVeh, true);

        rt.define_data_dword(
            DataDef::VmRegistersTlsIndex,
            *TLS_REGISTERS.get_or_init(|| unsafe { TlsAlloc() }),
        );
        rt.define_data_dword(
            DataDef::VmKeyTlsIndex,
            *TLS_KEY.get_or_init(|| unsafe { TlsAlloc() }),
        );
        rt.define_data_dword(
            DataDef::VmDebugTlsIndex,
            *TLS_DEBUG.get_or_init(|| unsafe { TlsAlloc() }),
        );
        rt.define_data_dword(
            DataDef::VmCleanupFlsIndex,
            *FLS_CLEANUP.get_or_init(|| unsafe { FlsAlloc(None) }),
        );

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

    pub fn run_virtual(&mut self, state: State, bytes: &[u8]) -> State {
        // call ...
        self.rt
            .asm
            .call(self.rt.function_labels[&FnDef::VmTInit])
            .unwrap();

        // mov r12d, [...]
        self.rt
            .asm
            .mov(
                r12d,
                ptr(self.rt.data_labels[&DataDef::VmRegistersTlsIndex]),
            )
            .unwrap();
        // mov r12, [0x1480 + r12*8]
        self.rt.asm.mov(r12, ptr(0x1480 + r12d * 8).gs()).unwrap();

        for (&register, &value) in &state.registers {
            // mov rax, ...
            self.rt.asm.mov(rax, value).unwrap();
            // mov [r12 + ...], rax
            self.rt
                .asm
                .mov(ptr(r12 + self.rt.mapper.index(register) * 8), rax)
                .unwrap();
        }

        // mov r8, [r12 + ...]
        self.rt
            .asm
            .mov(r8, ptr(r12 + self.rt.mapper.index(VMReg::VVector) * 8))
            .unwrap();

        let mut vectors = vec![[0u128; 2]; VECTORS.len()];

        for vector in VECTORS {
            if let Some(v) = state.vectors.get(&vector) {
                vectors[self.rt.mapper.index(vector) as usize] = *v;
            }
        }

        // mov r9, ...
        self.rt.asm.mov(r9, vectors.as_ptr() as u64).unwrap();

        for vector in VECTORS {
            // vmovdqu ymm0, [r9 + ...]
            self.rt
                .asm
                .vmovdqu(ymm0, ptr(r9 + self.rt.mapper.index(vector) as i32 * 32))
                .unwrap();
            // vmovdqu [r8 + ...], ymm0
            self.rt
                .asm
                .vmovdqu(ptr(r8 + self.rt.mapper.index(vector) as i32 * 32), ymm0)
                .unwrap();
        }

        // lea rcx, [...]
        self.rt
            .asm
            .lea(rcx, ptr(self.rt.data_labels[&DataDef::VmCode]))
            .unwrap();
        // call ...
        self.rt
            .asm
            .call(self.rt.function_labels[&FnDef::VmDispatch])
            .unwrap();

        let mut registers = [0u64; VMReg::COUNT];
        let mut vectors = [[0u128; 2]; VMVec::COUNT];

        // mov r8, ...
        self.rt.asm.mov(r8, registers.as_mut_ptr() as u64).unwrap();

        for register in REGISTERS {
            // mov r9, [r12 + ...]
            self.rt
                .asm
                .mov(r9, ptr(r12 + self.rt.mapper.index(register) * 8))
                .unwrap();
            // mov [r8 + ...], r9
            self.rt
                .asm
                .mov(ptr(r8 + self.rt.mapper.index(register) * 8), r9)
                .unwrap();
        }

        // mov r8, [r12 + ...]
        self.rt
            .asm
            .mov(r8, ptr(r12 + self.rt.mapper.index(VMReg::VVector) * 8))
            .unwrap();
        // mov r9, ...
        self.rt.asm.mov(r9, vectors.as_mut_ptr() as u64).unwrap();

        for vector in VECTORS {
            // vmovdqu ymm0, [r8 + ...]
            self.rt
                .asm
                .vmovdqu(ymm0, ptr(r8 + self.rt.mapper.index(vector) as i32 * 32))
                .unwrap();
            // vmovdqu [r9 + ...], ymm0
            self.rt
                .asm
                .vmovdqu(ptr(r9 + self.rt.mapper.index(vector) as i32 * 32), ymm0)
                .unwrap();
        }

        // ret
        self.rt.asm.ret().unwrap();

        self.rt.define_data_bytes(DataDef::VmCode, bytes);

        let ip = self.mem as u64;

        let code = self.rt.assemble(ip);

        unsafe {
            ptr::copy_nonoverlapping(code.as_ptr(), self.mem as *mut u8, code.len());
        }

        VIRTUAL_HANDLER.get_or_init(|| unsafe {
            AddVectoredExceptionHandler(1, Some(virtual_handler));
        });

        let mut thread_id = 0;

        let thread = unsafe {
            CreateThread(
                None,
                0,
                Some(mem::transmute::<
                    *const (),
                    unsafe extern "system" fn(*mut c_void) -> u32,
                >(self.mem as *const ())),
                Some(self.mem as *mut c_void),
                THREAD_CREATE_SUSPENDED,
                Some(&mut thread_id),
            )
            .unwrap()
        };

        VIRTUAL_REGISTRY.lock().unwrap().insert(thread_id);

        unsafe {
            ResumeThread(thread);
            WaitForSingleObject(thread, INFINITE);
            CloseHandle(thread).unwrap();
        }

        VIRTUAL_REGISTRY.lock().unwrap().remove(&thread_id);

        State {
            registers: REGISTERS
                .iter()
                .map(|&r| (r, registers[self.rt.mapper.index(r) as usize]))
                .collect(),
            vectors: VECTORS
                .iter()
                .map(|&v| (v, vectors[self.rt.mapper.index(v) as usize]))
                .collect(),
        }
    }

    pub fn run_native(&mut self, state: State, instructions: &[Instruction]) -> State {
        let ip = self.mem as u64;

        let result = BlockEncoder::encode(
            64,
            InstructionBlock::new(instructions, ip),
            BlockEncoderOptions::NONE,
        )
        .unwrap();

        unsafe {
            ptr::copy_nonoverlapping(
                result.code_buffer.as_ptr(),
                self.mem as *mut u8,
                result.code_buffer.len(),
            );
        }

        let limit = self.mem as usize + result.code_buffer.len();

        let initialized = AtomicBool::new(false);

        unsafe extern "system" fn spin(ready: *mut c_void) -> u32 {
            (*(ready as *const AtomicBool)).store(true, Ordering::SeqCst);

            loop {
                hint::spin_loop();
            }
        }

        let mut thread_id = 0u32;

        let thread = unsafe {
            CreateThread(
                None,
                0,
                Some(spin),
                Some(&initialized as *const AtomicBool as *const c_void),
                THREAD_CREATE_RUN_IMMEDIATELY,
                Some(&mut thread_id),
            )
            .unwrap()
        };

        while !initialized.load(Ordering::SeqCst) {
            hint::spin_loop();
        }

        unsafe {
            SuspendThread(thread);
        }

        let (_buffer, context) = initialize_context(CONTEXT_ALL_AMD64 | CONTEXT_XSTATE_AMD64);
        let context = unsafe {
            GetThreadContext(thread, context).unwrap();
            SetXStateFeaturesMask(context, XSTATE_MASK_AVX).unwrap();
            &mut *context
        };

        context.Rip = self.mem as u64;

        for (&register, &value) in &state.registers {
            write_register(context, register, value);
        }
        context.EFlags |= VMFlag::Trap.bit32();

        unsafe { write_vectors(context, &state.vectors) };

        NATIVE_HANDLER.get_or_init(|| unsafe {
            AddVectoredExceptionHandler(1, Some(native_handler));
        });

        NATIVE_REGISTRY
            .lock()
            .unwrap()
            .insert(thread_id, (context as *mut CONTEXT as usize, limit));

        unsafe {
            SetThreadContext(thread, context).unwrap();
            ResumeThread(thread);
            WaitForSingleObject(thread, INFINITE);
            CloseHandle(thread).unwrap();
        }

        NATIVE_REGISTRY.lock().unwrap().remove(&thread_id);

        context.EFlags &= !(VMFlag::Interrupt.bit32() | VMFlag::Reserved1.bit32());

        let registers = REGISTERS
            .iter()
            .map(|&register| (register, read_register(context, register)))
            .collect();
        let vectors = unsafe { read_vectors(context) };

        State { registers, vectors }
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
    ($code:ident, $a:expr, $b:expr, $c:expr) => {
        iced_x86::Instruction::with3(iced_x86::Code::$code, $a, $b, $c).unwrap()
    };
}

pub(crate) use instruction;
