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

const ACCUMULATOR: VMReg = VMReg::R13;

const NT_SET_INFORMATION_THREAD: VMReg = VMReg::R14;
const NT_QUERY_INFORMATION_THREAD: VMReg = VMReg::R15;

const NT_SET_INFORMATION_THREAD_PROLOGUE: [u8; 3] = [0x4C, 0x8B, 0xD1];
const NT_QUERY_INFORMATION_THREAD_PROLOGUE: [u8; 3] = [0x4C, 0x8B, 0xD1];

const NT_CURRENT_THREAD: i64 = -2;
const THREAD_HIDE_FROM_DEBUGGER: u64 = 0x11;

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

            b.extend(import(engine, ImportDef::NtSetInformationThread));
            b.extend(copy(VMReg::Rax, NT_SET_INFORMATION_THREAD));
            b.extend(accumulate_prologue(
                rng,
                ACCUMULATOR,
                NT_SET_INFORMATION_THREAD,
                &NT_SET_INFORMATION_THREAD_PROLOGUE,
                expected,
            ));
            b.extend(import(engine, ImportDef::NtQueryInformationThread));
            b.extend(copy(VMReg::Rax, NT_QUERY_INFORMATION_THREAD));
            b.extend(accumulate_prologue(
                rng,
                ACCUMULATOR,
                NT_QUERY_INFORMATION_THREAD,
                &NT_QUERY_INFORMATION_THREAD_PROLOGUE,
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
            b.extend(invoke(NT_SET_INFORMATION_THREAD));
            b.extend(accumulate(rng, ACCUMULATOR, VMReg::Rax, 0, expected));

            // ALLOCATE ThreadInformation
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

            // ThreadInformation -> R8
            b.extend(save(VMReg::R8));
            // ThreadHandle -> RCX
            b.extend(set(VMReg::Rcx, NT_CURRENT_THREAD as u64));
            // ThreadInformationClass -> RDX
            b.extend(set(VMReg::Rdx, THREAD_HIDE_FROM_DEBUGGER));
            // ThreadInformationLength -> R9
            b.extend(set(VMReg::R9, 1));
            // ReturnLength -> [RSP + ...]
            b.extend(store(VMReg::Rsp, VMReg::None, 1, 0x20, 0));
            // NtQueryInformationThread
            b.extend(invoke(NT_QUERY_INFORMATION_THREAD));
            // ACCUMULATE RAX
            b.extend(accumulate(rng, ACCUMULATOR, VMReg::Rax, 0, expected));
            // READ ThreadInformation[0]
            b.extend(accumulate_byte(
                rng,
                ACCUMULATOR,
                VMReg::VScratch,
                0,
                1,
                expected,
            ));
            // DISCARD ThreadInformation
            b.push(Rc::new(Discard));

            b.extend(release(0x28));

            b.extend(copy(ACCUMULATOR, VMReg::Vp0));

            b
        },
    )
}
