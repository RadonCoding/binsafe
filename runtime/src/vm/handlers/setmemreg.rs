use iced_x86::code_asm::{al, ax, bl, byte_ptr, eax, ptr, r12, r13, r14, r15, rax, rbx, rcx, rdx};

use crate::{
    runtime::{FnDef, Runtime},
    vm::bytecode::VMBits,
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut lower8 = rt.asm.create_label();
    let mut higher8 = rt.asm.create_label();
    let mut lower16 = rt.asm.create_label();
    let mut lower32 = rt.asm.create_label();
    let mut lower64 = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r12
    rt.asm.push(r12).unwrap();
    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();
    // push r15
    rt.asm.push(r15).unwrap();
    // push rbx
    rt.asm.push(rbx).unwrap();

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();
    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // mov bl, [r13] -> bits
    rt.asm.mov(bl, ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();

    // mov rcx, r12
    rt.asm.mov(rcx, r12).unwrap();
    // mov rdx, r13
    rt.asm.mov(rdx, r13).unwrap();
    // call ...
    rt.asm
        .call(rt.func_labels[&FnDef::ComputeEffectiveAddress])
        .unwrap();

    // mov r14, rax -> dst
    rt.asm.mov(r14, rax).unwrap();
    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // movzx r15, [r13] -> src
    rt.asm.movzx(r15, byte_ptr(r13)).unwrap();
    // dec r15
    rt.asm.dec(r15).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();

    // cmp bl, ...
    rt.asm.cmp(bl, VMBits::Lower64 as u8 as i32).unwrap();
    // je ...
    rt.asm.je(lower64).unwrap();
    // cmp bl, ...
    rt.asm.cmp(bl, VMBits::Lower32 as u8 as i32).unwrap();
    // je ...
    rt.asm.je(lower32).unwrap();
    // cmp bl, ...
    rt.asm.cmp(bl, VMBits::Lower16 as u8 as i32).unwrap();
    // je ...
    rt.asm.je(lower16).unwrap();
    // cmp bl, ...
    rt.asm.cmp(bl, VMBits::Higher8 as u8 as i32).unwrap();
    // je ...
    rt.asm.je(higher8).unwrap();

    rt.asm.set_label(&mut lower8).unwrap();
    {
        // mov al, [r12 + r15*8]
        rt.asm.mov(al, ptr(r12 + r15 * 8)).unwrap();
        // mov [r14], al
        rt.asm.mov(ptr(r14), al).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut higher8).unwrap();
    {
        // mov ax, [r12 + r15*8]
        rt.asm.mov(ax, ptr(r12 + r15 * 8)).unwrap();
        // shr ax, 0x8
        rt.asm.shr(ax, 0x8).unwrap();

        // mov [r14], al
        rt.asm.mov(ptr(r14), al).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower16).unwrap();
    {
        // mov ax, [r12 + r15*8]
        rt.asm.mov(ax, ptr(r12 + r15 * 8)).unwrap();

        // mov [r14], ax
        rt.asm.mov(ptr(r14), ax).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower32).unwrap();
    {
        // mov eax, [r12 + r15*8]
        rt.asm.mov(eax, ptr(r12 + r15 * 8)).unwrap();

        // mov [r14], eax
        rt.asm.mov(ptr(r14), eax).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower64).unwrap();
    {
        // mov rax, [r12 + r15*8]
        rt.asm.mov(rax, ptr(r12 + r15 * 8)).unwrap();

        // mov [r14], rax
        rt.asm.mov(ptr(r14), rax).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, r13
        rt.asm.mov(rax, r13).unwrap();
        // pop rbx
        rt.asm.pop(rbx).unwrap();
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
