use iced_x86::code_asm::{ax, byte_ptr, r8w, rax, rcx, rdx, word_ptr};

use crate::runtime::Runtime;

// bool (const unsigned short*, const char*)
pub fn build(rt: &mut Runtime) {
    let mut compare_loop = rt.asm.create_label();
    let mut not_equal = rt.asm.create_label();
    let mut is_equal = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // movzx ax, word ptr [rcx]
    rt.asm.movzx(ax, word_ptr(rcx)).unwrap();
    // movzx r8w, byte ptr [rdx]
    rt.asm.movzx(r8w, byte_ptr(rdx)).unwrap();

    rt.asm.set_label(&mut compare_loop).unwrap();
    {
        // cmp ax, r8w
        rt.asm.cmp(ax, r8w).unwrap();
        // jne ...
        rt.asm.jne(not_equal).unwrap();

        // test ax, ax
        rt.asm.test(ax, ax).unwrap();
        // jz ...
        rt.asm.jz(is_equal).unwrap();

        // add rcx, 0x2
        rt.asm.add(rcx, 0x2).unwrap();
        // add rdx, 0x1
        rt.asm.add(rdx, 0x1).unwrap();

        // movzx eax, word ptr [rcx]
        rt.asm.movzx(ax, word_ptr(rcx)).unwrap();
        // movzx r8d, byte ptr [rdx]
        rt.asm.movzx(r8w, byte_ptr(rdx)).unwrap();

        // jmp ...
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
