use iced_x86::code_asm::{al, byte_ptr, dl, ptr, r8, r9, rax, rcx, rdx};

use crate::runtime::Runtime;

// void (char*, u64)
pub fn build(rt: &mut Runtime) {
    let mut convert_loop = rt.asm.create_label();
    let mut reverse_loop = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // mov rax, rdx
    rt.asm.mov(rax, rdx).unwrap();
    // mov r9, 0xa
    rt.asm.mov(r9, 0xau64).unwrap();
    // mov r8, rcx
    rt.asm.mov(r8, rcx).unwrap();

    rt.asm.set_label(&mut convert_loop).unwrap();
    {
        // xor rdx, rdx
        rt.asm.xor(rdx, rdx).unwrap();
        // div r9
        rt.asm.div(r9).unwrap();
        // add dl, 0x30
        rt.asm.add(dl, 0x30).unwrap();
        // mov [r8], dl
        rt.asm.mov(ptr(r8), dl).unwrap();
        // inc r8
        rt.asm.inc(r8).unwrap();
        // test rax, rax
        rt.asm.test(rax, rax).unwrap();
        // jnz ...
        rt.asm.jne(convert_loop).unwrap();
    }

    // mov [r8], 0x0
    rt.asm.mov(byte_ptr(r8), 0x0).unwrap();
    // dec r8
    rt.asm.dec(r8).unwrap();

    rt.asm.set_label(&mut reverse_loop).unwrap();
    {
        // cmp rcx, r8
        rt.asm.cmp(rcx, r8).unwrap();
        // jge ...
        rt.asm.jge(epilogue).unwrap();
        // mov al, [rcx]
        rt.asm.mov(al, byte_ptr(rcx)).unwrap();
        // mov dl, [r8]
        rt.asm.mov(dl, byte_ptr(r8)).unwrap();
        // mov [rcx], dl
        rt.asm.mov(byte_ptr(rcx), dl).unwrap();
        // mov [r8], al
        rt.asm.mov(byte_ptr(r8), al).unwrap();
        // inc rcx
        rt.asm.inc(rcx).unwrap();
        // dec r8
        rt.asm.dec(r8).unwrap();
        // jmp ...
        rt.asm.jmp(reverse_loop).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // ret
        rt.asm.ret().unwrap();
    }
}
