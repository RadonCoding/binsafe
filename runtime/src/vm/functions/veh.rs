use iced_x86::code_asm::{byte_ptr, eax, ecx, ptr, r12, r12d, r13, r14, r15, rax, rcx, rdx, rsp};

use crate::{
    runtime::{BoolDef, DataDef, FnDef, ImportDef, Runtime},
    vm::{
        bytecode::VMReg,
        utils::{self},
    },
};

pub fn initialize(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // sub rsp, 0x20
    rt.asm.sub(rsp, 0x20).unwrap();

    // cmp [...], 0x1
    rt.asm
        .cmp(byte_ptr(rt.bool_labels[&BoolDef::VmHasVeh]), 0x1)
        .unwrap();
    // je ...
    rt.asm.je(epilogue).unwrap();

    // mov rcx, [...]; call ...
    rt.resolve(ImportDef::RtlAddVectoredExceptionHandler);

    // mov rcx, 0x1
    rt.asm.mov(rcx, 0x1u64).unwrap();
    // lea rdx, [...]
    rt.asm
        .lea(rdx, ptr(rt.function_labels[&FnDef::VmVehHandler]))
        .unwrap();
    // call rax
    rt.asm.call(rax).unwrap();

    // mov [...], 0x1
    rt.asm
        .mov(byte_ptr(rt.bool_labels[&BoolDef::VmHasVeh]), 0x1)
        .unwrap();

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // add rsp, 0x20
        rt.asm.add(rsp, 0x20).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}

const VM_TO_CONTEXT: &[(VMReg, i32)] = &[
    (VMReg::Rax, 0x78),
    (VMReg::Rcx, 0x80),
    (VMReg::Rdx, 0x88),
    (VMReg::Rbx, 0x90),
    (VMReg::Rsp, 0x98),
    (VMReg::Rbp, 0xA0),
    (VMReg::Rsi, 0xA8),
    (VMReg::Rdi, 0xB0),
    (VMReg::R8, 0xB8),
    (VMReg::R9, 0xC0),
    (VMReg::R10, 0xC8),
    (VMReg::R11, 0xD0),
    (VMReg::R13, 0xD8),
    (VMReg::R14, 0xE0),
    (VMReg::R15, 0xE8),
    (VMReg::R15, 0xF0),
    (VMReg::NEntry, 0xF8),
    (VMReg::Flags, 0x44),
];

// LONG (*EXCEPTION_POINTERS)
pub fn handler(rt: &mut Runtime) {
    let mut continue_search = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r12
    rt.asm.push(r12).unwrap();
    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();
    // push r15
    rt.asm.push(r15).unwrap();

    // sub rsp, 0x20
    rt.asm.sub(rsp, 0x20).unwrap();

    // mov r13, rcx
    rt.asm.mov(r13, rcx).unwrap();
    // mov r14, [r13] -> EXCEPTION_RECORD *EXCEPTION_POINTERS->ExceptionRecord
    rt.asm.mov(r14, ptr(r13)).unwrap();
    // mov r15, [r13 + 0x8] -> CONTEXT *EXCEPTION_POINTERS->ContextRecord
    rt.asm.mov(r15, ptr(r13 + 0x8)).unwrap();

    // mov ecx, [r14] -> DWORD EXCEPTION_RECORD->ExceptionCode
    rt.asm.mov(ecx, ptr(r14)).unwrap();
    // mov rdx, [r14 + 0x10] -> PVOID EXCEPTION_RECORD->ExceptionAddress
    rt.asm.mov(rdx, ptr(r14 + 0x10)).unwrap();

    #[cfg(debug_assertions)]
    {
        use crate::debug;

        let mut software_exception = rt.asm.create_label();

        // mov eax, ecx
        rt.asm.mov(eax, ecx).unwrap();
        // shr eax, 0x1c
        rt.asm.shr(eax, 0x1c).unwrap();
        // cmp eax, 0xc
        rt.asm.cmp(eax, 0xc).unwrap();
        // jne ...
        rt.asm.jne(software_exception).unwrap();

        debug::print_thread_message(rt, "ExceptionCode: ", Some(rcx), None);

        // mov rax, [r14 + 0x20] -> ULONG_PTR EXCEPTION_RECORD->ExceptionInformation[0]
        rt.asm.mov(rax, ptr(r14 + 0x20)).unwrap();
        debug::print_thread_message(rt, "ExceptionInformation[0]: ", Some(rax), None);
        // mov rax, [r14 + 0x28] -> ULONG_PTR EXCEPTION_RECORD->ExceptionInformation[1]
        rt.asm.mov(rax, ptr(r14 + 0x28)).unwrap();
        debug::print_thread_message(rt, "ExceptionInformation[1]: ", Some(rax), None);

        // mov rax, [rdx] -> ExceptionAddress[0..8]
        rt.asm.mov(rax, ptr(rdx)).unwrap();
        debug::print_thread_message(rt, "ExceptionAddress[0..8]: ", Some(rax), None);
        // mov rax, [rdx + 0x7] -> ExceptionAddress[7..15]
        rt.asm.mov(rax, ptr(rdx + 0x7)).unwrap();
        debug::print_thread_message(rt, "ExceptionAddress[7..15]: ", Some(rax), None);

        // mov rax, gs:[0x60] -> PEB *TEB->ProcessEnvironmentBlock
        rt.asm.mov(rax, ptr(0x60).gs()).unwrap();
        // mov rax, [rax + 0x10] -> PVOID PEB->ImageBaseAddress
        rt.asm.mov(rax, ptr(rax + 0x10)).unwrap();
        // sub rdx, rax
        rt.asm.sub(rdx, rax).unwrap();

        debug::print_thread_message(rt, "ExceptionAddress: ", Some(rdx), None);

        rt.asm.set_label(&mut software_exception).unwrap();
    }

    // lea rax, [...]
    rt.asm
        .lea(rax, ptr(rt.data_labels[&DataDef::VehStart]))
        .unwrap();
    // cmp rdx, rax
    rt.asm.cmp(rdx, rax).unwrap();
    // jb ...
    rt.asm.jb(continue_search).unwrap();

    // lea rax, [...]
    rt.asm
        .lea(rax, ptr(rt.data_labels[&DataDef::VehEnd]))
        .unwrap();
    // cmp rdx, rax
    rt.asm.cmp(rdx, rax).unwrap();
    // jae ...
    rt.asm.jae(continue_search).unwrap();

    // mov r12d, [...]
    rt.asm
        .mov(r12d, ptr(rt.data_labels[&DataDef::VmRegistersTlsIndex]))
        .unwrap();
    // mov r12, gs:[0x1480 + r12*8]
    rt.asm.mov(r12, ptr(0x1480 + r12 * 8).gs()).unwrap();

    for (register, offset) in VM_TO_CONTEXT {
        // mov rax, [rax + ...]
        utils::vreg::load_reg(rt, r12, *register, rax);

        if *register == VMReg::Flags {
            // mov [r15 + ...], eax
            rt.asm.mov(ptr(r15 + *offset), eax).unwrap();
        } else {
            // mov [r15 + ...], rax
            rt.asm.mov(ptr(r15 + *offset), rax).unwrap();
        }

        if *register == VMReg::NEntry {
            // mov [r14 + 0x10], rax -> PVOID EXCEPTION_RECORD->ExceptionAddress
            rt.asm.mov(ptr(r14 + 0x10), rax).unwrap();
        }
    }

    // xor rcx, rcx
    rt.asm.xor(rcx, rcx).unwrap();
    // call ...
    rt.asm.call(rt.function_labels[&FnDef::VmCrypt]).unwrap();

    // mov rax, -0x1 -> EXCEPTION_CONTINUE_EXECUTION
    rt.asm.mov(rax, -0x1i64 as u64).unwrap();
    // jmp ...
    rt.asm.jmp(epilogue).unwrap();

    rt.asm.set_label(&mut continue_search).unwrap();
    {
        // mov rax, 0x0 -> EXCEPTION_CONTINUE_SEARCH
        rt.asm.mov(rax, 0x0u64).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // add rsp, 0x20
        rt.asm.add(rsp, 0x20).unwrap();
        // pop r15
        rt.asm.pop(r15).unwrap();
        // pop r14
        rt.asm.pop(r14).unwrap();
        // pop r13
        rt.asm.pop(r13).unwrap();
        // pop r12
        rt.asm.pop(r12).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
