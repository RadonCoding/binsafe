use iced_x86::code_asm::{
    al, byte_ptr, eax, ptr, r12, r13, r13b, r14, r14b, r14d, r15, r8b, r9b, rax, rcx, rdx,
};

use crate::{
    runtime::{DataDef, Runtime},
    vm::stack,
};

// void (unsigned char*, unsigned short, bool)
pub fn build(rt: &mut Runtime) {
    let mut derive_key = rt.asm.create_label();
    let mut wait_for_previous = rt.asm.create_label();
    let mut wait_for_current = rt.asm.create_label();
    let mut crypt_loop = rt.asm.create_label();
    let mut is_decrypt = rt.asm.create_label();
    let mut continue_loop = rt.asm.create_label();
    let mut unlock = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);
    // push r14
    stack::push(rt, r14);
    // push r15
    stack::push(rt, r15);

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();
    // mov r13b, r8b
    rt.asm.mov(r13b, r8b).unwrap();
    // add rcx, 0x2
    rt.asm.add(rcx, 0x2).unwrap();
    // add rdx, rcx
    rt.asm.add(rdx, rcx).unwrap();

    // lea rax, [...]
    rt.asm
        .lea(rax, ptr(rt.data_labels[&DataDef::VmCode]))
        .unwrap();
    // mov r15, r12
    rt.asm.mov(r15, r12).unwrap();
    // sub r15, rax
    rt.asm.sub(r15, rax).unwrap();

    // test r8b, r8b
    rt.asm.test(r8b, r8b).unwrap();
    // jz ...
    rt.asm.jz(derive_key).unwrap();

    // test r15, r15
    rt.asm.test(r15, r15).unwrap();
    // jz ...
    rt.asm.jz(derive_key).unwrap();

    rt.asm.set_label(&mut wait_for_previous).unwrap();
    {
        // xor eax, eax
        rt.asm.xor(eax, eax).unwrap();
        // mov r9b, 0x1
        rt.asm.mov(r9b, 0x1u32).unwrap();
        // lock cmpxchg [r12 - 0x1], r9b
        rt.asm.lock().cmpxchg(byte_ptr(r12 - 0x1), r9b).unwrap();
        // jnz ...
        rt.asm.jnz(wait_for_previous).unwrap();
    }

    rt.asm.set_label(&mut wait_for_current).unwrap();
    {
        // xor eax, eax
        rt.asm.xor(eax, eax).unwrap();
        // mov r9b, 0x1
        rt.asm.mov(r9b, 0x1u32).unwrap();
        // lock cmpxchg [rdx], r9b
        rt.asm.lock().cmpxchg(byte_ptr(rdx), r9b).unwrap();
        // jnz ...
        rt.asm.jnz(wait_for_current).unwrap();
    }

    rt.asm.set_label(&mut derive_key).unwrap();
    {
        let mut load_key = rt.asm.create_label();

        // test r15, r15
        rt.asm.test(r15, r15).unwrap();
        // jnz ...
        rt.asm.jnz(load_key).unwrap();

        // mov r14, [...]
        rt.asm
            .mov(r14, ptr(rt.data_labels[&DataDef::VmKeySeed]))
            .unwrap();
        // jmp ...
        rt.asm.jmp(crypt_loop).unwrap();

        rt.asm.set_label(&mut load_key).unwrap();
        {
            // mov r14, [r12 - 0x4]
            rt.asm.mov(r14d, ptr(r12 - 0x5)).unwrap();
        }
    }

    rt.asm.set_label(&mut crypt_loop).unwrap();
    {
        // cmp rcx, rdx
        rt.asm.cmp(rcx, rdx).unwrap();
        // je ...
        rt.asm.je(unlock).unwrap();
        // mov al, [rcx]
        rt.asm.mov(al, byte_ptr(rcx)).unwrap();
        // xor [rcx], r14b
        rt.asm.xor(byte_ptr(rcx), r14b).unwrap();
        // test r13b, r13b
        rt.asm.test(r13b, r13b).unwrap();
        // jnz ...
        rt.asm.jnz(is_decrypt).unwrap();
        // movzx rax, [rcx]
        rt.asm.movzx(rax, byte_ptr(rcx)).unwrap();
        // jmp ...
        rt.asm.jmp(continue_loop).unwrap();

        rt.asm.set_label(&mut is_decrypt).unwrap();
        {
            // movzx rax, al
            rt.asm.movzx(rax, al).unwrap();
        }

        rt.asm.set_label(&mut continue_loop).unwrap();
        {
            // xor r14, rax
            rt.asm.xor(r14, rax).unwrap();
            // mov rax, [...]
            rt.asm
                .mov(rax, ptr(rt.data_labels[&DataDef::VmKeyMul]))
                .unwrap();
            // imul r14, rax
            rt.asm.imul_2(r14, rax).unwrap();
            // mov rax, [...]
            rt.asm
                .mov(rax, ptr(rt.data_labels[&DataDef::VmKeyAdd]))
                .unwrap();
            // add r14, rax
            rt.asm.add(r14, rax).unwrap();
            // inc rcx
            rt.asm.inc(rcx).unwrap();
            // jmp ...
            rt.asm.jmp(crypt_loop).unwrap();
        }
    }

    rt.asm.set_label(&mut unlock).unwrap();
    {
        // test r13b, r13b
        rt.asm.test(r13b, r13b).unwrap();
        // jnz ...
        rt.asm.jnz(epilogue).unwrap();

        // test r15, r15
        rt.asm.test(r15, r15).unwrap();
        // jz ...
        rt.asm.jz(epilogue).unwrap();

        // mov [r12 - 0x1], 0x0
        rt.asm.mov(byte_ptr(r12 - 0x1), 0x0u32).unwrap();
        // mov [rdx], 0x0
        rt.asm.mov(byte_ptr(rdx), 0x0u32).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // pop r15
        stack::pop(rt, r15);
        // pop r14
        stack::pop(rt, r14);
        // pop r13
        stack::pop(rt, r13);
        // pop r12
        stack::pop(rt, r12);
        // ret
        stack::ret(rt);
    }
}
