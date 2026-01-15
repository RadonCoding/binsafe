use iced_x86::code_asm::{
    al, byte_ptr, cl, eax, ecx, ptr, qword_ptr, r12, r13, r14, r8, r9b, rax, rcx, rdx, rsp,
};

use crate::{
    runtime::{BoolDef, DataDef, FnDef, Runtime, StringDef},
    vm::{bytecode::VMReg, stack, utils},
};

pub fn initialize(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // sub rsp, 0x28
    rt.asm.sub(rsp, 0x28).unwrap();

    // mov al, [...]
    rt.asm
        .mov(al, ptr(rt.bool_labels[&BoolDef::VmHasVeh]))
        .unwrap();
    // test al, al
    rt.asm.test(al, al).unwrap();
    // jnz ...
    rt.asm.jnz(epilogue).unwrap();

    // lea rcx, [...]; lea rdx, [...], call ...
    rt.get_proc_address(StringDef::Ntdll, StringDef::RtlAddVectoredExceptionHandler);

    // mov rcx, 0x1
    rt.asm.mov(rcx, 0x1u64).unwrap();
    // lea rdx, [...]
    rt.asm
        .lea(rdx, ptr(rt.func_labels[&FnDef::VmVehHandler]))
        .unwrap();
    // call rax
    rt.asm.call(rax).unwrap();

    // mov [...], 0x1
    rt.asm
        .mov(byte_ptr(rt.bool_labels[&BoolDef::VmHasVeh]), 0x1)
        .unwrap();

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // add rsp, 0x28
        rt.asm.add(rsp, 0x28).unwrap();
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
    (VMReg::R12, 0xD8),
    (VMReg::R13, 0xE0),
    (VMReg::R14, 0xE8),
    (VMReg::R15, 0xF0),
    (VMReg::Ven, 0xF8),
    (VMReg::Flags, 0x44),
];

pub const TRAP_MAGIC: u8 = 0x8E;

// long (*EXCEPTION_POINTERS)
pub fn handler(rt: &mut Runtime) {
    let mut check_range = rt.asm.create_label();
    let mut handle_trap = rt.asm.create_label();
    let mut continue_search = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r12
    rt.asm.push(r12).unwrap();
    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();

    // sub rsp, 0x28
    rt.asm.sub(rsp, 0x28).unwrap();

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();
    // mov r13, [r12] -> EXCEPTION_RECORD *EXCEPTION_POINTERS->ExceptionRecord
    rt.asm.mov(r13, ptr(r12)).unwrap();
    // mov r14, [r12 + 0x8] -> CONTEXT *EXCEPTION_POINTERS->ContextRecord
    rt.asm.mov(r14, ptr(r12 + 0x8)).unwrap();

    // mov eax, [r13] -> DWORD EXCEPTION_RECORD->ExceptionCode
    rt.asm.mov(eax, ptr(r13)).unwrap();
    // cmp eax, 0xC0000005
    rt.asm.cmp(eax, 0xC0000005u32).unwrap();
    // jne ...
    rt.asm.jne(check_range).unwrap();

    // mov rax, [r13 + 0x28] -> EXCEPTION_RECORD->ExceptionInformation[1]
    rt.asm.mov(rax, ptr(r13 + 0x28)).unwrap();

    // mov ecx, eax
    rt.asm.mov(ecx, eax).unwrap();
    // shr ecx, 0x18
    rt.asm.shr(ecx, 0x18).unwrap();
    // cmp cl, ...
    rt.asm.cmp(cl, TRAP_MAGIC as u32).unwrap();
    // je ...
    rt.asm.je(handle_trap).unwrap();

    rt.asm.set_label(&mut check_range).unwrap();
    {
        // mov rax, [r13 + 0x10] -> PVOID EXCEPTION_RECORD->ExceptionAddress
        rt.asm.mov(rax, ptr(r13 + 0x10)).unwrap();

        // lea rcx, [...]
        rt.asm
            .lea(rcx, ptr(rt.data_labels[&DataDef::VehStart]))
            .unwrap();
        // cmp rax, rcx
        rt.asm.cmp(rax, rcx).unwrap();
        // jb ...
        rt.asm.jb(continue_search).unwrap();

        // lea rcx, [...]
        rt.asm
            .lea(rcx, ptr(rt.data_labels[&DataDef::VehEnd]))
            .unwrap();
        // cmp rax, rcx
        rt.asm.cmp(rax, rcx).unwrap();
        // jae ...
        rt.asm.jae(continue_search).unwrap();
    }

    // mov eax, [...]
    rt.asm
        .mov(eax, ptr(rt.data_labels[&DataDef::VmStateTlsIndex]))
        .unwrap();
    // mov rax, gs:[0x1480 + rax*8]
    rt.asm.mov(rax, ptr(0x1480 + rax * 8).gs()).unwrap();

    for (vreg, offset) in VM_TO_CONTEXT {
        // mov rcx, [rax + ...]
        utils::mov_reg_vreg_64(rt, rax, *vreg, rcx);

        if *vreg == VMReg::Flags {
            // mov [r14 + ...], ecx
            rt.asm.mov(ptr(r14 + *offset), ecx).unwrap();
        } else {
            // mov [r14 + ...], rcx
            rt.asm.mov(ptr(r14 + *offset), rcx).unwrap();
        }

        if *vreg == VMReg::Ven {
            // mov [r13 + 0x10], rcx -> PVOID EXCEPTION_RECORD->ExceptionAddress
            rt.asm.mov(ptr(r13 + 0x10), rcx).unwrap();
        }
    }

    // mov rcx, [rax + ...]
    utils::mov_reg_vreg_64(rt, rax, VMReg::Vbp, rcx);
    // mov rdx, [rax + ...]
    utils::mov_reg_vreg_64(rt, rax, VMReg::Vbl, rdx);
    // mov r8, [r14 + ...]
    utils::mov_reg_vreg_64(rt, r12, VMReg::Vsk, r8);
    // xor r9b, r9b
    rt.asm.xor(r9b, r9b).unwrap();
    // call ...
    stack::call(rt, rt.func_labels[&FnDef::VmCrypt]);

    // mov rax, -0x1 -> EXCEPTION_CONTINUE_EXECUTION
    rt.asm.mov(rax, -0x1i64 as u64).unwrap();
    // jmp ...
    rt.asm.jmp(epilogue).unwrap();

    rt.asm.set_label(&mut handle_trap).unwrap();
    {
        // mov ecx, eax
        rt.asm.mov(ecx, eax).unwrap();
        // shr ecx, 0x10
        rt.asm.shr(ecx, 0x10).unwrap();
        // and ecx, 0xFF
        rt.asm.and(ecx, 0xFFu32).unwrap();

        // mov rax, [r14 + 0xE0] -> DWORD64 CONTEXT->R13
        rt.asm.mov(rax, ptr(r14 + 0xE0)).unwrap();
        // add rax, rcx
        rt.asm.add(rax, rcx).unwrap();
        // mov [r14 + 0xE0], rax -> DWORD64 CONTEXT->R13
        rt.asm.mov(ptr(r14 + 0xE0), rax).unwrap();

        // add [r14 + 0xF8], 0x7 -> CONTEXT->Rip
        rt.asm.add(qword_ptr(r14 + 0xF8), 0x7).unwrap();

        // mov rax, -0x1 -> EXCEPTION_CONTINUE_EXECUTION
        rt.asm.mov(rax, -0x1i64 as u64).unwrap();
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut continue_search).unwrap();
    {
        // mov rax, 0x0 -> EXCEPTION_CONTINUE_SEARCH
        rt.asm.mov(rax, 0x0u64).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // add rsp, 0x28
        rt.asm.add(rsp, 0x28).unwrap();
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
