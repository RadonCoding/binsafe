use iced_x86::code_asm::{al, byte_ptr, ptr, r10, r8, r9, rax, rcx, rdx};

use crate::{runtime::Runtime, vm::bytecode::VMBits};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut lower8 = rt.asm.create_label();
    let mut higher8 = rt.asm.create_label();
    let mut lower16 = rt.asm.create_label();
    let mut lower32 = rt.asm.create_label();
    let mut lower64 = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // mov al, [rdx] -> bits
    rt.asm.mov(al, ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // movzx r8, [rdx] -> dst
    rt.asm.movzx(r8, byte_ptr(rdx)).unwrap();
    // dec r8
    rt.asm.dec(r8).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // movzx r9, [rdx] -> src
    rt.asm.movzx(r9, byte_ptr(rdx)).unwrap();
    // dec r9
    rt.asm.dec(r9).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // cmp al, ...
    rt.asm.cmp(al, VMBits::Lower64 as u8 as i32).unwrap();
    // je ...
    rt.asm.je(lower64).unwrap();
    // cmp al, ...
    rt.asm.cmp(al, VMBits::Lower32 as u8 as i32).unwrap();
    // je ...
    rt.asm.je(lower32).unwrap();
    // cmp al, ...
    rt.asm.cmp(al, VMBits::Lower16 as u8 as i32).unwrap();
    // je ...
    rt.asm.je(lower16).unwrap();
    // cmp al, ...
    rt.asm.cmp(al, VMBits::Higher8 as u8 as i32).unwrap();
    // je ...
    rt.asm.je(higher8).unwrap();

    rt.asm.set_label(&mut lower8).unwrap();
    {
        // mov rax, [rcx + r9*8]
        rt.asm.mov(rax, ptr(rcx + r9 * 8)).unwrap();
        // and rax, 0xFF
        rt.asm.and(rax, 0xFF).unwrap();

        // mov r10, [rcx + r8*8]
        rt.asm.mov(r10, ptr(rcx + r8 * 8)).unwrap();
        // and r10, !0xFF
        rt.asm.and(r10, !0xFFi32).unwrap();
        // or r10, rax
        rt.asm.or(r10, rax).unwrap();

        // mov [rcx + r8*8], r10
        rt.asm.mov(ptr(rcx + r8 * 8), r10).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut higher8).unwrap();
    {
        // mov rax, [rcx + r9*8]
        rt.asm.mov(rax, ptr(rcx + r9 * 8)).unwrap();
        // and rax, 0xFF
        rt.asm.and(rax, 0xFF).unwrap();
        // shl rax, 0x8
        rt.asm.shl(rax, 0x8).unwrap();

        // mov r10, [rcx + r8*8]
        rt.asm.mov(r10, ptr(rcx + r8 * 8)).unwrap();
        // and r10, !0xFF00
        rt.asm.and(r10, !0xFF00i32).unwrap();
        // or r10, rax
        rt.asm.or(r10, rax).unwrap();

        // mov [rcx + r8*8], r10
        rt.asm.mov(ptr(rcx + r8 * 8), r10).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower16).unwrap();
    {
        // mov rax, [rcx + r9*8]
        rt.asm.mov(rax, ptr(rcx + r9 * 8)).unwrap();
        // and rax, 0xFFFF
        rt.asm.and(rax, 0xFFFF).unwrap();

        // mov r10, [rcx + r8*8]
        rt.asm.mov(r10, ptr(rcx + r8 * 8)).unwrap();
        // and r10, !0xFFFF
        rt.asm.and(r10, !0xFFFFi32).unwrap();
        // or r10, rax
        rt.asm.or(r10, rax).unwrap();

        // mov [rcx + r8*8], r10
        rt.asm.mov(ptr(rcx + r8 * 8), r10).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower32).unwrap();
    {
        // mov eax, [rcx + r9 * 8]
        rt.asm.mov(rax, ptr(rcx + r9 * 8)).unwrap();
        // mov [rcx + r8 * 8], rax
        rt.asm.mov(ptr(rcx + r8 * 8), rax).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower64).unwrap();
    {
        // mov rax, [rcx + r9 * 8]
        rt.asm.mov(rax, ptr(rcx + r9 * 8)).unwrap();
        // mov [rcx + r8 * 8], rax
        rt.asm.mov(ptr(rcx + r8 * 8), rax).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
