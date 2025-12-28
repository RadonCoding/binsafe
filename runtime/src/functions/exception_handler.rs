use iced_x86::code_asm::{eax, ptr, r12, r13, r14, rax, rcx};

use crate::runtime::{FnDef, Runtime};

// long (*EXCEPTION_POINTERS)
pub fn build(rt: &mut Runtime) {
    let mut handle_breakpoint = rt.asm.create_label();
    let mut continue_execution = rt.asm.create_label();
    let mut continue_search = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r12
    rt.asm.push(r12).unwrap();
    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();

    // mov r12, rcx -> *EXCEPTION_POINTERS
    rt.asm.mov(r12, rcx).unwrap();

    // mov rax, [r12] -> EXCEPTION_RECORD *EXCEPTION_POINTERS->ExceptionRecord
    rt.asm.mov(rax, ptr(r12)).unwrap();
    // mov eax, [rax] -> DWORD EXCEPTION_RECORD->ExceptionCode
    rt.asm.mov(eax, ptr(rax)).unwrap();

    // cmp eax, 0x80000003 -> EXCEPTION_BREAKPOINT
    rt.asm.cmp(eax, 0x80000003u32).unwrap();
    // je ...
    rt.asm.je(handle_breakpoint).unwrap();

    // jmp ...
    rt.asm.jmp(continue_execution).unwrap();

    rt.asm.set_label(&mut handle_breakpoint).unwrap();
    {
        // mov rcx, [r12 + 0x8] -> CONTEXT *EXCEPTION_POINTERS->ContextRecord
        rt.asm.mov(rcx, ptr(r12 + 0x8)).unwrap();
        // call ...
        rt.asm.call(rt.func_labels[&FnDef::VmEntryPoint]).unwrap();
        // test rax, rax
        rt.asm.test(rax, rax).unwrap();
        // jnz ...
        rt.asm.jnz(continue_execution).unwrap();
        // jmp ...
        rt.asm.jmp(continue_search).unwrap();
    }

    rt.asm.set_label(&mut continue_execution).unwrap();
    {
        // mov rax, 0xFFFFFFFF -> EXCEPTION_CONTINUE_EXECUTION
        rt.asm.mov(rax, 0xFFFFFFFFu64).unwrap();
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
