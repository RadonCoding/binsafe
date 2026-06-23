use std::rc::Rc;

use crate::engine::Engine;
use crate::protections::virtualization::attestation::*;
use rand::Rng;
use runtime::runtime::ImportDef;
use runtime::vm::bytecode::{VMMem, VMReg, VMSeg, VMWidth};
use runtime::vm::encoders::discard::Discard;
use runtime::vm::encoders::load_address::LoadAddress;
use runtime::vm::encoders::load_immediate::LoadImmediate;
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
) -> Vec<Rc<dyn Encode>> {
    skip(
        engine,
        VMReg::Vp0,
        VMCondition::cmp(VMFlag::Zero, 0),
        |engine| {
            let mut b = Vec::<Rc<dyn Encode>>::new();

            b.extend(set(ACCUMULATOR, 0));

            b.extend(reserve(0x28));

            b.extend(query_process_debug_object_handle(engine, rng, expected));
            b.extend(set_hide_from_debugger(engine, rng, expected));
            b.extend(query_hide_from_debbuger(engine, rng, expected));

            b.extend(release(0x28));

            b.extend(copy(ACCUMULATOR, VMReg::Vp0));

            b
        },
    )
}

fn query_process_debug_object_handle(
    engine: &mut Engine,
    rng: &mut impl Rng,
    expected: &mut u64,
) -> Vec<Rc<dyn Encode>> {
    let mut b = Vec::new();

    b.extend(import(engine, ImportDef::NtQueryInformationProcess));
    b.extend(accumulate_prologue(
        rng,
        ACCUMULATOR,
        VMReg::Rax,
        &NT_QUERY_INFORMATION_PROCESS_PROLOGUE,
        expected,
    ));
    // ALLOCATE ProcessDebugObjectHandle
    b.push(Rc::new(LoadImmediate {
        width: VMWidth::Lower64,
        source: 0u64.to_le_bytes().to_vec(),
    }));
    b.push(Rc::new(LoadAddress {
        source: VMMem {
            base: VMReg::VScratch,
            index: VMReg::None,
            scale: 1,
            displacement: 0,
            segment: VMSeg::None,
        },
    }));
    // ProcessHandle -> RCX
    b.extend(set(VMReg::Rcx, NT_CURRENT_PROCESS as u64));
    // ProcessInformationClass -> RDX
    b.extend(set(VMReg::Rdx, PROCESS_DEBUG_OBJECT_HANDLE));
    // ProcessInformation -> R8
    b.extend(save(VMReg::R8));
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
        VMReg::VScratch,
        0,
        VMWidth::Lower64,
        0,
        expected,
    ));
    // DISCARD ProcessDebugObjectHandle
    b.push(Rc::new(Discard));

    b
}

fn set_hide_from_debugger(
    engine: &mut Engine,
    rng: &mut impl Rng,
    expected: &mut u64,
) -> Vec<Rc<dyn Encode>> {
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
) -> Vec<Rc<dyn Encode>> {
    let mut b = Vec::new();

    b.extend(import(engine, ImportDef::NtQueryInformationThread));
    b.extend(accumulate_prologue(
        rng,
        ACCUMULATOR,
        VMReg::Rax,
        &NT_QUERY_INFORMATION_THREAD_PROLOGUE,
        expected,
    ));
    // ALLOCATE ThreadHideFromDebugger
    b.push(Rc::new(LoadImmediate {
        width: VMWidth::Lower8,
        source: vec![0],
    }));
    b.push(Rc::new(LoadAddress {
        source: VMMem {
            base: VMReg::VScratch,
            index: VMReg::None,
            scale: 1,
            displacement: 0,
            segment: VMSeg::None,
        },
    }));
    // ThreadHandle -> RCX
    b.extend(set(VMReg::Rcx, NT_CURRENT_THREAD as u64));
    // ThreadInformationClass -> RDX
    b.extend(set(VMReg::Rdx, THREAD_HIDE_FROM_DEBUGGER));
    // ThreadInformation -> R8
    b.extend(save(VMReg::R8));
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
        VMReg::VScratch,
        0,
        1,
        expected,
    ));
    // DISCARD ThreadHideFromDebugger
    b.push(Rc::new(Discard));

    b
}
