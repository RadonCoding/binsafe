#![cfg(test)]

use std::{
    collections::HashMap,
    ffi::c_void,
    hint, mem, ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        LazyLock, Mutex, OnceLock,
    },
};

use crate::{
    constants::{VIRTUAL_REGISTERS, VIRTUAL_VECTORS},
    instrumentation::{
        initialize_context, native_handler, read_register, read_vectors, virtual_handler,
        write_register, write_vectors,
    },
};
use iced_x86::{
    code_asm::{ptr, r12, r12d, r8, r9, rax, ymm0},
    BlockEncoder, BlockEncoderOptions, Instruction, InstructionBlock,
};
use obfuscator::protections::virtualization::crypt;
use runtime::{
    mapper::Mappable,
    runtime::{BoolDef, DataDef, FnDef, Runtime},
    vm::{
        bytecode::{Flag, VMReg, VMVec},
        utils,
    },
};
use windows::Win32::{
    Foundation::CloseHandle,
    System::{
        Diagnostics::Debug::{
            AddVectoredExceptionHandler, GetThreadContext, SetThreadContext, SetXStateFeaturesMask,
            CONTEXT, CONTEXT_ALL_AMD64, CONTEXT_XSTATE_AMD64,
        },
        Memory::{
            VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        },
        Threading::{
            CreateThread, FlsAlloc, ResumeThread, SuspendThread, TlsAlloc, WaitForSingleObject,
            INFINITE, THREAD_CREATE_RUN_IMMEDIATELY, THREAD_CREATE_SUSPENDED,
        },
    },
};

mod constants;
mod instructions;
mod instrumentation;

static TLS_REGISTERS: OnceLock<u32> = OnceLock::new();
static TLS_KEY: OnceLock<u32> = OnceLock::new();
static TLS_DEBUG: OnceLock<u32> = OnceLock::new();
static FLS_CLEANUP: OnceLock<u32> = OnceLock::new();

static NATIVE_REGISTRY: LazyLock<Mutex<HashMap<u32, (usize, usize, usize, Option<u32>)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NATIVE_HANDLER: OnceLock<()> = OnceLock::new();

static VIRTUAL_REGISTRY: LazyLock<Mutex<HashMap<u32, Option<u32>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static VIRTUAL_HANDLER: OnceLock<()> = OnceLock::new();

const XSTATE_AVX: u32 = 2;
const XSTATE_MASK_AVX: u64 = 4;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct State {
    pub registers: HashMap<VMReg, u64>,
    pub vectors: HashMap<VMVec, [u128; 2]>,
    pub exception: Option<u32>,
}

pub enum Difference {
    Register(VMReg, u64, u64),
    Vector(VMVec, [u128; 2], [u128; 2]),
    Exception(u32, u32),
}

impl State {
    pub fn with<T: TryInto<u64>>(mut self, register: VMReg, value: T) -> Self
    where
        T::Error: std::fmt::Debug,
    {
        self.registers.insert(register, value.try_into().unwrap());
        self
    }

    pub fn zeroed(self, register: VMReg) -> Self {
        self.with(register, 0u64)
    }

    pub fn compare(&self, other: &Self) -> Vec<Difference> {
        let mut differences = Vec::new();

        match (self.exception, other.exception) {
            (Some(native), Some(virtual_)) => {
                if native != virtual_ {
                    differences.push(Difference::Exception(native, virtual_));
                }

                return differences;
            }
            (Some(native), None) => {
                differences.push(Difference::Exception(native, 0));
                return differences;
            }
            (None, Some(virtual_)) => {
                differences.push(Difference::Exception(0, virtual_));
                return differences;
            }
            (None, None) => {}
        }

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

pub struct Executor {
    pub rt: Runtime,
    pub memory: *mut c_void,
}

impl Executor {
    pub const TEST_KEY_INITIALIZER: u64 = 0x1234567890ABCDEF;
    pub const TEST_KEY_MULTIPLIER: u64 = 0x1234567890ABCDEF;
    pub const TEST_KEY_ADDEND: u64 = 0x1234567890ABCDEF;

    pub const SIZE: usize = 0x100000;

    pub fn new() -> Self {
        let mut rt = Runtime::new(64);

        rt.define_data_qword(DataDef::VmKeyInitializer, Self::TEST_KEY_INITIALIZER);
        rt.define_data_qword(DataDef::VmKeyMultiplier, Self::TEST_KEY_MULTIPLIER);
        rt.define_data_qword(DataDef::VmKeyAddend, Self::TEST_KEY_ADDEND);

        rt.define_bool(BoolDef::HasVeh, true);

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

        let memory = unsafe {
            VirtualAlloc(
                None,
                Self::SIZE,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };

        Self { rt, memory }
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
                .mov(ptr(r12 + self.rt.mapper.index(register) as i32 * 8), rax)
                .unwrap();
        }

        // mov r8, [r12 + ...]
        self.rt
            .asm
            .mov(
                r8,
                ptr(r12 + self.rt.mapper.index(VMReg::VVector) as i32 * 8),
            )
            .unwrap();

        let mut vectors = vec![[0u128; 2]; VIRTUAL_VECTORS.len()];

        for vector in VIRTUAL_VECTORS {
            if let Some(v) = state.vectors.get(&vector) {
                vectors[self.rt.mapper.index(vector) as usize] = *v;
            }
        }

        // mov r9, ...
        self.rt.asm.mov(r9, vectors.as_ptr() as u64).unwrap();

        for vector in VIRTUAL_VECTORS {
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

        // lea rax, [...]
        self.rt
            .asm
            .lea(rax, ptr(self.rt.data_labels[&DataDef::VmCode]))
            .unwrap();
        // mov [r12 + ...], rax
        utils::vreg::store_reg(&mut self.rt, r12, rax, VMReg::BPointer);

        // call ...
        self.rt
            .asm
            .call(self.rt.function_labels[&FnDef::VmDispatch])
            .unwrap();

        let mut registers = [0u64; VMReg::COUNT];
        let mut vectors = [[0u128; 2]; VMVec::COUNT];

        // mov r8, ...
        self.rt.asm.mov(r8, registers.as_mut_ptr() as u64).unwrap();

        for register in VIRTUAL_REGISTERS {
            // mov r9, [r12 + ...]
            self.rt
                .asm
                .mov(r9, ptr(r12 + self.rt.mapper.index(register) as i32 * 8))
                .unwrap();
            // mov [r8 + ...], r9
            self.rt
                .asm
                .mov(ptr(r8 + self.rt.mapper.index(register) as i32 * 8), r9)
                .unwrap();
        }

        // mov r8, [r12 + ...]
        self.rt
            .asm
            .mov(
                r8,
                ptr(r12 + self.rt.mapper.index(VMReg::VVector) as i32 * 8),
            )
            .unwrap();
        // mov r9, ...
        self.rt.asm.mov(r9, vectors.as_mut_ptr() as u64).unwrap();

        for vector in VIRTUAL_VECTORS {
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

        let ip = self.memory as u64;

        let code = self.rt.assemble(ip);

        assert!(code.len() <= Self::SIZE);

        unsafe {
            ptr::copy_nonoverlapping(code.as_ptr(), self.memory as *mut u8, code.len());
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
                >(self.memory as *const ())),
                Some(self.memory as *mut c_void),
                THREAD_CREATE_SUSPENDED,
                Some(&mut thread_id),
            )
            .unwrap()
        };

        VIRTUAL_REGISTRY.lock().unwrap().insert(thread_id, None);

        unsafe {
            ResumeThread(thread);
            WaitForSingleObject(thread, INFINITE);
            CloseHandle(thread).unwrap();
        }

        let exception = VIRTUAL_REGISTRY
            .lock()
            .unwrap()
            .remove(&thread_id)
            .flatten();

        State {
            registers: VIRTUAL_REGISTERS
                .iter()
                .map(|&r| (r, registers[self.rt.mapper.index(r) as usize]))
                .collect(),
            vectors: VIRTUAL_VECTORS
                .iter()
                .map(|&v| (v, vectors[self.rt.mapper.index(v) as usize]))
                .collect(),
            exception,
        }
    }

    pub fn run_native(&mut self, state: State, instructions: &[Instruction]) -> State {
        let ip = self.memory as u64;

        let result = BlockEncoder::encode(
            64,
            InstructionBlock::new(instructions, ip),
            BlockEncoderOptions::NONE,
        )
        .unwrap();

        unsafe {
            ptr::copy_nonoverlapping(
                result.code_buffer.as_ptr(),
                self.memory as *mut u8,
                result.code_buffer.len(),
            );
        }

        let base = self.memory as usize;
        let limit = base + result.code_buffer.len();

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

        context.Rip = self.memory as u64;

        for (&register, &value) in &state.registers {
            write_register(context, register, value);
        }
        context.EFlags |= Flag::Trap.bit32();

        unsafe { write_vectors(context, &state.vectors) };

        NATIVE_HANDLER.get_or_init(|| unsafe {
            AddVectoredExceptionHandler(1, Some(native_handler));
        });

        NATIVE_REGISTRY.lock().unwrap().insert(
            thread_id,
            (context as *mut CONTEXT as usize, base, limit, None),
        );

        unsafe {
            SetThreadContext(thread, context).unwrap();
            ResumeThread(thread);
            WaitForSingleObject(thread, INFINITE);
            CloseHandle(thread).unwrap();
        }

        let exception = NATIVE_REGISTRY
            .lock()
            .unwrap()
            .remove(&thread_id)
            .and_then(|(_, _, _, exception)| exception);

        context.EFlags &= !(Flag::Interrupt.bit32() | Flag::Reserved1.bit32());

        let registers = VIRTUAL_REGISTERS
            .iter()
            .map(|&register| (register, read_register(context, register)))
            .collect();
        let vectors = unsafe { read_vectors(context) };

        State {
            registers,
            vectors,
            exception,
        }
    }
}

impl Drop for Executor {
    fn drop(&mut self) {
        unsafe {
            let _ = VirtualFree(self.memory, 0, MEM_RELEASE);
        }
    }
}

pub fn encrypt_block(block: &mut Vec<u8>) {
    crypt::encrypt_block(
        block,
        Executor::TEST_KEY_INITIALIZER,
        Executor::TEST_KEY_MULTIPLIER,
        Executor::TEST_KEY_ADDEND,
        0,
    );
}

pub fn decrypt_payload(block: &mut Vec<u8>) {
    crypt::decrypt_payload(
        block,
        Executor::TEST_KEY_INITIALIZER,
        Executor::TEST_KEY_MULTIPLIER,
        Executor::TEST_KEY_ADDEND,
        0,
    );
}

pub fn decrypt_block(block: &mut Vec<u8>) {
    crypt::decrypt_block(
        block,
        Executor::TEST_KEY_INITIALIZER,
        Executor::TEST_KEY_MULTIPLIER,
        Executor::TEST_KEY_ADDEND,
        0,
    );
}
