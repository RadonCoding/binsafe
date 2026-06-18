use std::{collections::HashMap, ffi::c_void, ptr};

use crate::{constants::VECTORS, NATIVE_REGISTRY, VIRTUAL_REGISTRY, XSTATE_AVX};
use runtime::vm::bytecode::{VMFlag, VMReg, VMVec};
use windows::Win32::{
    Foundation::EXCEPTION_SINGLE_STEP,
    System::{
        Diagnostics::Debug::{
            InitializeContext, LocateXStateFeature, CONTEXT, CONTEXT_FLAGS,
            EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS, M128A,
        },
        Threading::{GetCurrentThread, GetCurrentThreadId, TerminateThread},
    },
};

pub unsafe extern "system" fn virtual_handler(_info: *mut EXCEPTION_POINTERS) -> i32 {
    if VIRTUAL_REGISTRY
        .lock()
        .unwrap()
        .contains(&GetCurrentThreadId())
    {
        TerminateThread(GetCurrentThread(), 0).unwrap();
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    EXCEPTION_CONTINUE_SEARCH
}

pub unsafe extern "system" fn native_handler(info: *mut EXCEPTION_POINTERS) -> i32 {
    let entry = NATIVE_REGISTRY
        .lock()
        .unwrap()
        .get(&GetCurrentThreadId())
        .copied();

    if let Some((context, limit)) = entry {
        if (*(*info).ExceptionRecord).ExceptionCode == EXCEPTION_SINGLE_STEP {
            let rip = (*(*info).ContextRecord).Rip as usize;

            if rip < limit {
                (*(*info).ContextRecord).EFlags |= VMFlag::Trap.bit32();
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            ptr::copy_nonoverlapping((*info).ContextRecord, context as *mut CONTEXT, 1);
        } else {
            eprintln!(
                "EXCEPTION: 0x{:08X}",
                (*(*info).ExceptionRecord).ExceptionCode.0
            );
        }

        TerminateThread(GetCurrentThread(), 0).unwrap();

        return EXCEPTION_CONTINUE_EXECUTION;
    }
    EXCEPTION_CONTINUE_SEARCH
}

pub fn write_register(context: &mut CONTEXT, register: VMReg, value: u64) {
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

pub fn read_register(context: &CONTEXT, register: VMReg) -> u64 {
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

pub unsafe fn write_vectors(context: &mut CONTEXT, vectors: &HashMap<VMVec, [u128; 2]>) {
    let upper = LocateXStateFeature(context, XSTATE_AVX, None) as *mut M128A;

    for (&vector, &value) in vectors {
        let index = VECTORS.iter().position(|&v| v == vector).unwrap();
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

pub unsafe fn read_vectors(context: &mut CONTEXT) -> HashMap<VMVec, [u128; 2]> {
    let upper = LocateXStateFeature(context, XSTATE_AVX, None) as *const M128A;

    VECTORS
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

pub fn initialize_context(flags: CONTEXT_FLAGS) -> (Vec<u8>, *mut CONTEXT) {
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
