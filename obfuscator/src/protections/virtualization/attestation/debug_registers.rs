use crate::engine::Engine;
use crate::protections::virtualization::attestation::*;
use runtime::runtime::ImportDef;
use runtime::vm::bytecode::{VMReg, VMSeg, VMWidth};
use runtime::vm::encoders::Encode;

const NT_GET_CONTEXT_THREAD_PROLOGUE: [u8; 3] = [0x4C, 0x8B, 0xD1];

const NT_CURRENT_THREAD: i64 = -2;

const STATUS_SUCCESS: u64 = 0;

const CONTEXT_DEBUG_REGISTERS: u64 = 0x0010_0010;

const DR0: i32 = 0x68;
const DR1: i32 = 0x70;
const DR2: i32 = 0x78;
const DR3: i32 = 0x80;
const DR7: i32 = 0x90;

pub fn generate(engine: &mut Engine, expected: &mut u64) -> Vec<Box<dyn Encode>> {
    let mut b = Vec::<Box<dyn Encode>>::new();

    b.extend(reserve(0x4F0));

    b.extend(import(engine, ImportDef::NtGetContextThread));
    b.extend(accumulate_prologue(
        engine,
        VMReg::Vp0,
        VMReg::Rax,
        &NT_GET_CONTEXT_THREAD_PROLOGUE,
        expected,
    ));
    // ThreadHandle -> RCX
    b.extend(set_register(VMReg::Rcx, NT_CURRENT_THREAD as u64));
    // ThreadContext -> RDX
    b.extend(compute_memory(
        VMReg::Rsp,
        VMReg::None,
        1,
        0x20,
        VMSeg::None,
    ));
    b.extend(store_register(VMReg::Rdx));
    // ContextFlags -> [RSP + ...]
    b.extend(store_immediate(
        VMReg::Rsp,
        VMReg::None,
        1,
        0x50,
        CONTEXT_DEBUG_REGISTERS,
    ));
    // NtGetContextThread
    b.extend(invoke(VMReg::Rax));

    b.extend(accumulate_immediate(
        engine,
        VMReg::Vp0,
        Some(VMReg::Rax),
        STATUS_SUCCESS,
        expected,
    ));

    // Read Dr0..Dr3 + Dr7:
    for displacement in [DR0, DR1, DR2, DR3, DR7] {
        b.extend(accumulate_memory(
            engine,
            VMReg::Vp0,
            VMReg::Rsp,
            displacement,
            VMWidth::Lower64,
            0,
            expected,
        ));
    }

    b.extend(release(0x4F0));

    b
}
