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

use iced_x86::{
    code_asm::{ptr, r12, r12d, r8, r9, rax, rcx, ymm0},
    Instruction,
};
use obfuscator::protections::virtualization::crypt;
use runtime::{
    mapper::Mappable,
    runtime::{DataDef, FnDef, Runtime},
    vm::bytecode::{VMFlag, VMReg, VMVec},
};
use windows::Win32::{
    Foundation::{CloseHandle, EXCEPTION_SINGLE_STEP},
    System::{
        Diagnostics::Debug::{
            AddVectoredExceptionHandler, GetThreadContext, InitializeContext, LocateXStateFeature,
            SetThreadContext, SetXStateFeaturesMask, CONTEXT, CONTEXT_ALL_AMD64, CONTEXT_FLAGS,
            CONTEXT_XSTATE_AMD64, EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH,
            EXCEPTION_POINTERS, M128A,
        },
        Memory::{
            VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
            PAGE_EXECUTE_READWRITE, PAGE_READWRITE,
        },
        Threading::{
            CreateThread, ExitThread, FlsAlloc, GetCurrentThreadId, ResumeThread, SuspendThread,
            TlsAlloc, WaitForSingleObject, INFINITE, THREAD_CREATE_RUN_IMMEDIATELY,
        },
    },
};

mod instructions;
mod permutation;

const NATIVE: [VMReg; 17] = [
    VMReg::Rax,
    VMReg::Rcx,
    VMReg::Rdx,
    VMReg::Rbx,
    VMReg::Rsp,
    VMReg::Rbp,
    VMReg::Rsi,
    VMReg::Rdi,
    VMReg::R8,
    VMReg::R9,
    VMReg::R10,
    VMReg::R11,
    VMReg::R12,
    VMReg::R13,
    VMReg::R14,
    VMReg::R15,
    VMReg::Flags,
];

const XSTATE_AVX: u32 = 2;
const XSTATE_MASK_AVX: u64 = 4;

pub(crate) const FAKE_BRANCH_ADDRESS: u64 = 0x1234_ABCD;

static TLS_REGISTERS: OnceLock<u32> = OnceLock::new();
static TLS_KEY: OnceLock<u32> = OnceLock::new();
static FLS_CLEANUP: OnceLock<u32> = OnceLock::new();

static FAKE_BRANCH_MAPPED: OnceLock<()> = OnceLock::new();

static NATIVE_REGISTRY: LazyLock<Mutex<HashMap<u32, (usize, usize)>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static NATIVE_HANDLER: OnceLock<()> = OnceLock::new();

unsafe extern "system" fn native_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    if (*(*info).ExceptionRecord).ExceptionCode == EXCEPTION_SINGLE_STEP {
        let entry = NATIVE_REGISTRY
            .lock()
            .unwrap()
            .get(&GetCurrentThreadId())
            .copied();

        if let Some((context, ready)) = entry {
            ptr::copy_nonoverlapping((*info).ContextRecord, context as *mut CONTEXT, 1);

            (*(ready as *const AtomicBool)).store(true, Ordering::SeqCst);

            let record = (*info).ContextRecord;
            (*record).EFlags &= !0x100;
            (*record).Rsp = ((*record).Rsp & !0xF) - 8;
            (*record).Rcx = 0;
            (*record).Rip = ExitThread as *const () as u64;

            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    EXCEPTION_CONTINUE_SEARCH
}

fn initialize_context(flags: CONTEXT_FLAGS) -> (Vec<u8>, *mut CONTEXT) {
    let mut length = 0;

    unsafe {
        let _ = InitializeContext(None, flags, ptr::null_mut(), &mut length);
    }

    let mut buffer = vec![0u8; length as usize];
    let mut context = ptr::null_mut();

    unsafe {
        InitializeContext(
            Some(buffer.as_mut_ptr() as *mut c_void),
            flags,
            &mut context,
            &mut length,
        )
        .unwrap();
    }

    (buffer, context)
}

fn initialize_threads() -> [(DataDef, u32); 3] {
    [
        (
            DataDef::VmRegistersTlsIndex,
            *TLS_REGISTERS.get_or_init(|| unsafe { TlsAlloc() }),
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
    pub fn with(mut self, register: VMReg, value: u64) -> Self {
        self.registers.insert(register, value);
        self
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
                Some((FAKE_BRANCH_ADDRESS & !0xFFFF) as *const c_void),
                Self::SIZE,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
        });

        let mut rt = Runtime::new(64);

        rt.define_data_qword(DataDef::VmKeySeed, Self::TEST_KEY_SEED);
        rt.define_data_qword(DataDef::VmKeyMul, Self::TEST_KEY_MUL);
        rt.define_data_qword(DataDef::VmKeyAdd, Self::TEST_KEY_ADD);

        for (def, value) in initialize_threads() {
            rt.define_data_dword(def, value);
        }

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
        // xor rcx, rcx
        self.rt.asm.xor(rcx, rcx).unwrap();
        // call ...
        self.rt
            .asm
            .call(self.rt.function_labels[&FnDef::VmHandlersInitialize])
            .unwrap();

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

        let mut vectors = vec![[0u128; 2]; VMVec::VARIANTS.len()];

        for &vector in VMVec::VARIANTS {
            if let Some(v) = state.vectors.get(&vector) {
                vectors[self.rt.mapper.index(vector) as usize] = *v;
            }
        }

        // mov r9, ...
        self.rt.asm.mov(r9, vectors.as_ptr() as u64).unwrap();

        for &vector in VMVec::VARIANTS {
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

        for register in NATIVE {
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

        for &vector in VMVec::VARIANTS {
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

        assert!(code.len() <= Self::SIZE);

        unsafe {
            ptr::copy_nonoverlapping(code.as_ptr(), self.mem as *mut u8, code.len());
        }

        let thread = unsafe {
            CreateThread(
                None,
                0,
                Some(mem::transmute::<
                    *const (),
                    unsafe extern "system" fn(*mut c_void) -> u32,
                >(self.mem as *const ())),
                Some(self.mem as *mut c_void),
                THREAD_CREATE_RUN_IMMEDIATELY,
                None,
            )
            .unwrap()
        };

        unsafe {
            WaitForSingleObject(thread, INFINITE);
            CloseHandle(thread).unwrap();
        }

        State {
            registers: NATIVE
                .iter()
                .map(|&r| (r, registers[self.rt.mapper.index(r) as usize]))
                .collect(),
            vectors: VMVec::VARIANTS
                .iter()
                .map(|&v| (v, vectors[self.rt.mapper.index(v) as usize]))
                .collect(),
        }
    }

    pub fn run_native(&mut self, state: State, instruction: &Instruction) -> State {
        self.rt.asm.add_instruction(*instruction).unwrap();

        let ip = self.mem as u64;

        let code = self.rt.assemble(ip);

        unsafe {
            ptr::copy_nonoverlapping(code.as_ptr(), self.mem as *mut u8, code.len());
        }

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

        let ready = AtomicBool::new(false);

        NATIVE_HANDLER.get_or_init(|| unsafe {
            AddVectoredExceptionHandler(1, Some(native_handler));
        });

        NATIVE_REGISTRY.lock().unwrap().insert(
            thread_id,
            (
                context as *mut CONTEXT as usize,
                &ready as *const AtomicBool as usize,
            ),
        );

        unsafe {
            SetThreadContext(thread, context).unwrap();
            ResumeThread(thread);
        }

        while !ready.load(Ordering::SeqCst) {
            hint::spin_loop();
        }

        unsafe {
            CloseHandle(thread).unwrap();
        }

        NATIVE_REGISTRY.lock().unwrap().remove(&thread_id);

        context.EFlags &= !(VMFlag::Interrupt.bit32() | VMFlag::Reserved1.bit32());

        let registers = NATIVE
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

fn write_register(context: &mut CONTEXT, register: VMReg, value: u64) {
    match register {
        VMReg::Rax => context.Rax = value,
        VMReg::Rcx => context.Rcx = value,
        VMReg::Rdx => context.Rdx = value,
        VMReg::Rbx => context.Rbx = value,
        VMReg::Rsp => context.Rsp = value,
        VMReg::Rbp => context.Rbp = value,
        VMReg::Rsi => context.Rsi = value,
        VMReg::Rdi => context.Rdi = value,
        VMReg::R8 => context.R8 = value,
        VMReg::R9 => context.R9 = value,
        VMReg::R10 => context.R10 = value,
        VMReg::R11 => context.R11 = value,
        VMReg::R12 => context.R12 = value,
        VMReg::R13 => context.R13 = value,
        VMReg::R14 => context.R14 = value,
        VMReg::R15 => context.R15 = value,
        VMReg::Flags => context.EFlags = value as u32,
        _ => {}
    }
}

fn read_register(context: &CONTEXT, register: VMReg) -> u64 {
    match register {
        VMReg::Rax => context.Rax,
        VMReg::Rcx => context.Rcx,
        VMReg::Rdx => context.Rdx,
        VMReg::Rbx => context.Rbx,
        VMReg::Rsp => context.Rsp,
        VMReg::Rbp => context.Rbp,
        VMReg::Rsi => context.Rsi,
        VMReg::Rdi => context.Rdi,
        VMReg::R8 => context.R8,
        VMReg::R9 => context.R9,
        VMReg::R10 => context.R10,
        VMReg::R11 => context.R11,
        VMReg::R12 => context.R12,
        VMReg::R13 => context.R13,
        VMReg::R14 => context.R14,
        VMReg::R15 => context.R15,
        VMReg::Flags => context.EFlags as u64,
        _ => 0,
    }
}

unsafe fn write_vectors(context: &mut CONTEXT, vectors: &HashMap<VMVec, [u128; 2]>) {
    let upper = LocateXStateFeature(context, XSTATE_AVX, None) as *mut M128A;

    for (&vector, &value) in vectors {
        let index = VMVec::VARIANTS.iter().position(|&v| v == vector).unwrap();
        context.Anonymous.FltSave.XmmRegisters[index] = M128A {
            Low: value[0] as u64,
            High: (value[0] >> 64) as i64,
        };
        *upper.add(index) = M128A {
            Low: value[1] as u64,
            High: (value[1] >> 64) as i64,
        };
    }
}

unsafe fn read_vectors(context: &mut CONTEXT) -> HashMap<VMVec, [u128; 2]> {
    let upper = LocateXStateFeature(context, XSTATE_AVX, None) as *const M128A;

    VMVec::VARIANTS
        .iter()
        .enumerate()
        .map(|(index, &vector)| {
            let low = context.Anonymous.FltSave.XmmRegisters[index];
            let high = if upper.is_null() {
                M128A::default()
            } else {
                *upper.add(index)
            };
            let value = [
                low.Low as u128 | ((low.High as u64 as u128) << 64),
                high.Low as u128 | ((high.High as u64 as u128) << 64),
            ];
            (vector, value)
        })
        .collect()
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
