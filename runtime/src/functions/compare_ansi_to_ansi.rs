use crate::runtime::Runtime;

use iced_x86::code_asm::{al, ptr, r8b, rax, rcx, rdx};

// bool (const char*, const char*)
pub fn build(rt: &mut Runtime) {
    let mut compare_loop = rt.asm.create_label();
    let mut not_equal = rt.asm.create_label();
    let mut is_equal = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // mov al, [rcx]
    rt.asm.mov(al, ptr(rcx)).unwrap();
    // mov r8b, [rdx]
    rt.asm.mov(r8b, ptr(rdx)).unwrap();

    rt.asm.set_label(&mut compare_loop).unwrap();
    {
        // cmp al, bl
        rt.asm.cmp(al, r8b).unwrap();
        // jne ...
        rt.asm.jne(not_equal).unwrap();

        // test al, al
        rt.asm.test(al, al).unwrap();
        // jz ...
        rt.asm.jz(is_equal).unwrap();

        // inc rcx
        rt.asm.inc(rcx).unwrap();
        // inc rdx
        rt.asm.inc(rdx).unwrap();

        // mov al, [rcx]
        rt.asm.mov(al, ptr(rcx)).unwrap();
        // mov r8b, [rdx]
        rt.asm.mov(r8b, ptr(rdx)).unwrap();

        // jmp ...
        rt.asm.jmp(compare_loop).unwrap();
    }

    rt.asm.set_label(&mut not_equal).unwrap();
    {
        // mov rax, 0x0
        rt.asm.mov(rax, 0x0u64).unwrap();
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut is_equal).unwrap();
    {
        // mov rax, 0x1
        rt.asm.mov(rax, 0x1u64).unwrap();
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // ret
        rt.asm.ret().unwrap();
    }
}
