use iced_x86::code_asm::{ptr, rax, rcx};

use crate::runtime::{FnDef, Runtime};

pub fn build(rt: &mut Runtime) {
    let mut executed = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // mov rcx, [rcx + 0x8] -> CONTEXT *EXCEPTION_POINTERS->ContextRecord
    rt.asm.mov(rcx, ptr(rcx + 0x8)).unwrap();

    // call ...
    rt.asm.call(rt.func_labels[&FnDef::VmEntryPoint]).unwrap();
    // test rax, rax
    rt.asm.test(rax, rax).unwrap();
    // jnz ...
    rt.asm.jnz(executed).unwrap();

    // mov rax, 0x0 -> EXCEPTION_CONTINUE_SEARCH
    rt.asm.mov(rax, 0x0u64).unwrap();
    // jmp ...
    rt.asm.jmp(epilogue).unwrap();

    rt.asm.set_label(&mut executed).unwrap();
    {
        // mov rax, 0xFFFFFFFF -> EXCEPTION_CONTINUE_EXECUTION
        rt.asm.mov(rax, 0xFFFFFFFFu64).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // ret
        rt.asm.ret().unwrap();
    }
}
