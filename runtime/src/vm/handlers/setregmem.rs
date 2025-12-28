use iced_x86::code_asm::{
    bl, byte_ptr, eax, ptr, r12, r13, r14, r15, rax, rbx, rcx, rdx, word_ptr,
};

use crate::{
    runtime::{FnDef, Runtime},
    vm::bytecode::VMBits,
    vm::stack,
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
    stack::stack_push(rt, r12);
    // push r13
    stack::stack_push(rt, r13);
    // push r14
    stack::stack_push(rt, r14);
    // push r15
    stack::stack_push(rt, r15);
    // push rbx
    stack::stack_push(rt, rbx);

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();
    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // mov bl, [r13] -> bits
    rt.asm.mov(bl, ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();

    // movzx r15, [r13] -> dst
    rt.asm.movzx(r15, byte_ptr(r13)).unwrap();
    // dec r15
    rt.asm.dec(r15).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();

    // mov rcx, r12
    rt.asm.mov(rcx, r12).unwrap();
    // mov rdx, r13
    rt.asm.mov(rdx, r13).unwrap();
    // call ...
    stack::call(rt, rt.func_labels[&FnDef::ComputeEffectiveAddress]);

    // mov r14, rax -> src
    rt.asm.mov(r14, rax).unwrap();
    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

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
        // mov rax, [r14]
        rt.asm.mov(rax, ptr(r14)).unwrap();

        // mov rcx, [r12 + r15*8]
        rt.asm.mov(rcx, ptr(r12 + r15 * 8)).unwrap();
        // and rcx, !0xFF
        rt.asm.and(rcx, !0xFFi32).unwrap();
        // or rcx, rax
        rt.asm.or(rcx, rax).unwrap();

        // mov [r12 + r15*8], rcx
        rt.asm.mov(ptr(r12 + r15 * 8), rcx).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut higher8).unwrap();
    {
        // mov rax, [r14]
        rt.asm.mov(rax, ptr(r14)).unwrap();
        // shl rax, 0x8
        rt.asm.shl(rax, 0x8).unwrap();

        // mov rcx, [r12 + r15*8]
        rt.asm.mov(rcx, ptr(r12 + r15 * 8)).unwrap();
        // and rcx, !0xFF00
        rt.asm.and(rcx, !0xFF00i32).unwrap();
        // or rcx, rax
        rt.asm.or(rcx, rax).unwrap();

        // mov [r12 + r15*8], rcx
        rt.asm.mov(ptr(r12 + r15 * 8), rcx).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower16).unwrap();
    {
        // mov rax, [r14]
        rt.asm.mov(rax, word_ptr(r14)).unwrap();

        // mov rcx, [r12 + r15*8]
        rt.asm.mov(rcx, ptr(r12 + r15 * 8)).unwrap();
        // and rcx, !0xFFFF
        rt.asm.and(rcx, !0xFFFFi32).unwrap();
        // or rcx, rax
        rt.asm.or(rcx, rax).unwrap();

        // mov [r12 + r15*8], rcx
        rt.asm.mov(ptr(r12 + r15 * 8), rcx).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower32).unwrap();
    {
        // mov eax, [r14]
        rt.asm.mov(eax, ptr(r14)).unwrap();

        // mov [r12 + r15*8], rax
        rt.asm.mov(ptr(r12 + r15 * 8), rax).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower64).unwrap();
    {
        // mov rax, [r14]
        rt.asm.mov(rax, ptr(r14)).unwrap();

        // mov [r12 + r15*8], rax
        rt.asm.mov(ptr(r12 + r15 * 8), rax).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, r13
        rt.asm.mov(rax, r13).unwrap();
        // pop rbx
        stack::stack_pop(rt, rbx);
        // pop r15
        stack::stack_pop(rt, r15);
        // pop r14
        stack::stack_pop(rt, r14);
        // pop r13
        stack::stack_pop(rt, r13);
        // pop r12
        stack::stack_pop(rt, r12);
        // ret
        stack::ret(rt);
    }
}
