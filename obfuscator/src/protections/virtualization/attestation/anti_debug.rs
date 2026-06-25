use crate::engine::Engine;
use crate::protections::virtualization::attestation::*;
use rand::Rng;
use runtime::runtime::ImportDef;
use runtime::vm::bytecode::{VMReg, VMSeg, VMWidth};
use runtime::vm::encoders::Encode;

const ACCUMULATOR: VMReg = VMReg::Rbx;

const NT_QUERY_INFORMATION_PROCESS_PROLOGUE: [u8; 3] = [0x4C, 0x8B, 0xD1];
const NT_SET_INFORMATION_THREAD_PROLOGUE: [u8; 3] = [0x4C, 0x8B, 0xD1];
const NT_QUERY_INFORMATION_THREAD_PROLOGUE: [u8; 3] = [0x4C, 0x8B, 0xD1];

const NT_CURRENT_PROCESS: i64 = -1;
const NT_CURRENT_THREAD: i64 = -2;

const PROCESS_DEBUG_OBJECT_HANDLE: u64 = 0x1e;
const THREAD_HIDE_FROM_DEBUGGER: u64 = 0x11;

const STATUS_PORT_NOT_SET: u64 = 0xc0000353;
const STATUS_SUCCESS: u64 = 0;

pub fn generate(
    engine: &mut Engine,
    rng: &mut impl Rng,
    expected: &mut u64,
    mix: u32,
) -> Vec<Box<dyn Encode>> {
    let mut instructions = Vec::<Box<dyn Encode>>::new();

    instructions.extend(reserve(0x30));

    instructions.extend(set(ACCUMULATOR, 0));

    instructions.extend(query_process_debug_object_handle(engine, rng, expected));
    instructions.extend(set_hide_from_debugger(engine, rng, expected));
    instructions.extend(query_hide_from_debbuger(engine, rng, expected));

    instructions.extend(spill(ACCUMULATOR));
    instructions.extend(spill(VMReg::Vt0));
    instructions.extend(create(mix));
    instructions.extend(reload(VMReg::Vp0));

    instructions.extend(release(0x30));

    instructions
}

fn query_process_debug_object_handle(
    engine: &mut Engine,
    rng: &mut impl Rng,
    expected: &mut u64,
) -> Vec<Box<dyn Encode>> {
    let mut b = Vec::new();

    b.extend(import(engine, ImportDef::NtQueryInformationProcess));
    b.extend(accumulate_prologue(
        rng,
        ACCUMULATOR,
        VMReg::Rax,
        &NT_QUERY_INFORMATION_PROCESS_PROLOGUE,
        expected,
    ));
    // ProcessHandle -> RCX
    b.extend(set(VMReg::Rcx, NT_CURRENT_PROCESS as u64));
    // ProcessInformationClass -> RDX
    b.extend(set(VMReg::Rdx, PROCESS_DEBUG_OBJECT_HANDLE));
    // ALLOCATE ProcessDebugObjectHandle
    b.extend(compute(VMReg::Rsp, VMReg::None, 1, 0x28, VMSeg::None));
    // ProcessInformation -> R8
    b.extend(reload(VMReg::R8));
    // ProcessInformationLength -> R9
    b.extend(set(VMReg::R9, 8));
    // ReturnLength -> [RSP + ...]
    b.extend(store(VMReg::Rsp, VMReg::None, 1, 0x20, 0));
    // NtQueryInformationProcess
    b.extend(invoke(VMReg::Rax));

    b.extend(accumulate(
        rng,
        ACCUMULATOR,
        VMReg::Rax,
        STATUS_PORT_NOT_SET,
        expected,
    ));

    // READ ProcessDebugObjectHandle
    b.extend(accumulate_memory(
        rng,
        ACCUMULATOR,
        VMReg::Rsp,
        0x28,
        VMWidth::Lower64,
        0,
        expected,
    ));

    b
}

fn set_hide_from_debugger(
    engine: &mut Engine,
    rng: &mut impl Rng,
    expected: &mut u64,
) -> Vec<Box<dyn Encode>> {
    let mut b = Vec::new();

    b.extend(import(engine, ImportDef::NtSetInformationThread));
    b.extend(accumulate_prologue(
        rng,
        ACCUMULATOR,
        VMReg::Rax,
        &NT_SET_INFORMATION_THREAD_PROLOGUE,
        expected,
    ));
    // ThreadHandle -> RCX
    b.extend(set(VMReg::Rcx, NT_CURRENT_THREAD as u64));
    // ThreadInformationClass -> RDX
    b.extend(set(VMReg::Rdx, THREAD_HIDE_FROM_DEBUGGER));
    // ThreadInformation -> R8
    b.extend(set(VMReg::R8, 0));
    // ThreadInformationLength -> R9
    b.extend(set(VMReg::R9, 0));
    // NtSetInformationThread
    b.extend(invoke(VMReg::Rax));

    b.extend(accumulate(
        rng,
        ACCUMULATOR,
        VMReg::Rax,
        STATUS_SUCCESS,
        expected,
    ));

    b
}

fn query_hide_from_debbuger(
    engine: &mut Engine,
    rng: &mut impl Rng,
    expected: &mut u64,
) -> Vec<Box<dyn Encode>> {
    let mut b = Vec::new();

    b.extend(import(engine, ImportDef::NtQueryInformationThread));
    b.extend(accumulate_prologue(
        rng,
        ACCUMULATOR,
        VMReg::Rax,
        &NT_QUERY_INFORMATION_THREAD_PROLOGUE,
        expected,
    ));

    // ThreadHandle -> RCX
    b.extend(set(VMReg::Rcx, NT_CURRENT_THREAD as u64));
    // ThreadInformationClass -> RDX
    b.extend(set(VMReg::Rdx, THREAD_HIDE_FROM_DEBUGGER));
    // ALLOCATE ThreadHideFromDebugger
    b.extend(compute(VMReg::Rsp, VMReg::None, 1, 0x28, VMSeg::None));
    // ThreadInformation -> R8
    b.extend(reload(VMReg::R8));
    // ThreadInformationLength -> R9
    b.extend(set(VMReg::R9, 1));
    // ReturnLength -> [RSP + ...]
    b.extend(store(VMReg::Rsp, VMReg::None, 1, 0x20, 0));
    // NtQueryInformationThread
    b.extend(invoke(VMReg::Rax));

    b.extend(accumulate(
        rng,
        ACCUMULATOR,
        VMReg::Rax,
        STATUS_SUCCESS,
        expected,
    ));

    // READ ThreadHideFromDebugger
    b.extend(accumulate_byte(
        rng,
        ACCUMULATOR,
        VMReg::Rsp,
        0x28,
        1,
        expected,
    ));

    b
}
