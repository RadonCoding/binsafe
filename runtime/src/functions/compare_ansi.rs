use crate::runtime::Runtime;
use iced_x86::code_asm::{al, byte_ptr, r8b, rax, rcx, rdx, word_ptr};

// bool (const char*, const char*)
pub fn build(rt: &mut Runtime) {
    let mut compare_loop = rt.asm.create_label();
    let mut not_equal = rt.asm.create_label();
    let mut is_equal = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // mov al, byte ptr [rcx]
    rt.asm.mov(al, word_ptr(rcx)).unwrap();
    // mov r8b, byte ptr [rdx]
    rt.asm.mov(r8b, byte_ptr(rdx)).unwrap();

    rt.asm.set_label(&mut compare_loop).unwrap();
    {
        // cmp al, bl
        rt.asm.cmp(al, r8b).unwrap();
        // jne not_equal
        rt.asm.jne(not_equal).unwrap();

        // test al, al
        rt.asm.test(al, al).unwrap();
        // jz is_equal
        rt.asm.jz(is_equal).unwrap();

        // inc rcx
        rt.asm.inc(rcx).unwrap();
        // inc rdx
        rt.asm.inc(rdx).unwrap();

        // mov al, byte ptr [rcx]
        rt.asm.mov(al, word_ptr(rcx)).unwrap();
        // mov r8b, byte ptr [rdx]
        rt.asm.mov(r8b, byte_ptr(rdx)).unwrap();

        // jmp compare_loop
        rt.asm.jmp(compare_loop).unwrap();
    }

    rt.asm.set_label(&mut not_equal).unwrap();
    {
        // mov rax, 0x0
        rt.asm.mov(rax, 0u64).unwrap();
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut is_equal).unwrap();
    {
        // mov rax, 0x1
        rt.asm.mov(rax, 1u64).unwrap();
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // ret
        rt.asm.ret().unwrap();
    }
}
