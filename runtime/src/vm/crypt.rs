use iced_x86::code_asm::{byte_ptr, eax, ptr, r12, r13, r13b, r14, r15, r8, r9b, rax, rcx, rdx};

use crate::{
    runtime::{DataDef, Runtime},
    vm::stack,
};

// void (unsigned char*, unsigned long, unsigned char*, bool)
pub fn build(rt: &mut Runtime) {
    let mut decrypting = rt.asm.create_label();
    let mut wait_for_previous_spin = rt.asm.create_label();
    let mut wait_for_previous_cas = rt.asm.create_label();
    let mut wait_for_current_spin = rt.asm.create_label();
    let mut wait_for_current_cas = rt.asm.create_label();
    let mut derive_key = rt.asm.create_label();
    let mut start_key = rt.asm.create_label();
    let mut save_key = rt.asm.create_label();
    let mut crypt_loop = rt.asm.create_label();
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
    // mov r13b, r9b
    rt.asm.mov(r13b, r9b).unwrap();

    // add rcx, 0x2
    rt.asm.add(rcx, 0x2).unwrap();

    // add rdx, 0x7
    rt.asm.add(rdx, 0x7).unwrap();
    // and rdx, -0x8
    rt.asm.and(rdx, -0x8).unwrap();
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

    // test r13b, r13b
    rt.asm.test(r13b, r13b).unwrap();
    // jnz ... -> decrypting
    rt.asm.jnz(decrypting).unwrap();

    // mov eax, [...]
    rt.asm
        .mov(eax, ptr(rt.data_labels[&DataDef::VmCacheTlsIndex]))
        .unwrap();
    // mov r14, gs:[0x1480 + rax * 8]
    rt.asm.mov(r14, ptr(0x1480 + rax * 8).gs()).unwrap();
    // jmp ...
    rt.asm.jmp(crypt_loop).unwrap();

    rt.asm.set_label(&mut decrypting).unwrap();
    {
        // test r15, r15
        rt.asm.test(r15, r15).unwrap();
        // jz ... -> first block
        rt.asm.jz(start_key).unwrap();

        rt.asm.set_label(&mut wait_for_previous_spin).unwrap();
        {
            // cmp byte [r12 - 0x1], 0x0
            rt.asm.cmp(byte_ptr(r12 - 0x1), 0x0).unwrap();
            // pause
            rt.asm.pause().unwrap();
            // jne ...
            rt.asm.jne(wait_for_previous_spin).unwrap();
        }

        rt.asm.set_label(&mut wait_for_previous_cas).unwrap();
        {
            // xor eax, eax
            rt.asm.xor(eax, eax).unwrap();
            // mov r9b, 0x1
            rt.asm.mov(r9b, 0x1).unwrap();
            // lock cmpxchg [r12 - 0x1], r9b
            rt.asm.lock().cmpxchg(byte_ptr(r12 - 0x1), r9b).unwrap();
            // jnz ...
            rt.asm.jnz(wait_for_previous_spin).unwrap();
        }
    }

    rt.asm.set_label(&mut derive_key).unwrap();
    {
        // mov r14, [r12 - 0x8]
        rt.asm.mov(r14, ptr(r12 - 0x8)).unwrap();
        // mov rax, 0x00FFFFFFFFFFFFFF
        rt.asm.mov(rax, 0x00FFFFFFFFFFFFFFu64).unwrap();
        // and r14, rax
        rt.asm.and(r14, rax).unwrap();

        // mov [r12 - 0x1], 0x0 -> release previous
        rt.asm.mov(byte_ptr(r12 - 0x1), 0x0).unwrap();

        // jmp ...
        rt.asm.jmp(save_key).unwrap();
    }

    rt.asm.set_label(&mut start_key).unwrap();
    {
        // mov r14, [...]
        rt.asm
            .mov(r14, ptr(rt.data_labels[&DataDef::VmKeySeed]))
            .unwrap();
    }

    rt.asm.set_label(&mut save_key).unwrap();
    {
        // mov eax, [...]
        rt.asm
            .mov(eax, ptr(rt.data_labels[&DataDef::VmCacheTlsIndex]))
            .unwrap();
        // mov gs:[0x1480 + rax * 8], r14
        rt.asm.mov(ptr(0x1480 + rax * 8).gs(), r14).unwrap();
    }

    rt.asm.set_label(&mut wait_for_current_spin).unwrap();
    {
        // cmp [rdx], 0x0
        rt.asm.cmp(byte_ptr(rdx), 0x0).unwrap();
        // pause
        rt.asm.pause().unwrap();
        // jne ...
        rt.asm.jne(wait_for_current_spin).unwrap();
    }

    rt.asm.set_label(&mut wait_for_current_cas).unwrap();
    {
        // xor eax, eax
        rt.asm.xor(eax, eax).unwrap();
        // mov r9b, 0x1
        rt.asm.mov(r9b, 0x1).unwrap();
        // lock cmpxchg [rdx], r9b
        rt.asm.lock().cmpxchg(byte_ptr(rdx), r9b).unwrap();
        // jnz ...
        rt.asm.jnz(wait_for_current_spin).unwrap();
    }

    rt.asm.set_label(&mut crypt_loop).unwrap();
    {
        // cmp rcx, rdx
        rt.asm.cmp(rcx, rdx).unwrap();
        // je ...
        rt.asm.je(unlock).unwrap();

        // mov rax, [rcx]
        rt.asm.mov(rax, ptr(rcx)).unwrap();
        // xor [rcx], r14
        rt.asm.xor(ptr(rcx), r14).unwrap();

        // test r13b, r13b
        rt.asm.test(r13b, r13b).unwrap();
        // jnz ... -> decrypting
        rt.asm.jnz(continue_loop).unwrap();

        // mov rax, [rcx]
        rt.asm.mov(rax, ptr(rcx)).unwrap();

        rt.asm.set_label(&mut continue_loop).unwrap();
        {
            // xor r14, rax
            rt.asm.xor(r14, rax).unwrap();

            // movzx rax, [r8]
            rt.asm.movzx(rax, byte_ptr(r8)).unwrap();
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

            // add rcx, 0x8
            rt.asm.add(rcx, 0x8).unwrap();
            // jmp ...
            rt.asm.jmp(crypt_loop).unwrap();
        }
    }

    rt.asm.set_label(&mut unlock).unwrap();
    {
        // test r13b, r13b
        rt.asm.test(r13b, r13b).unwrap();
        // jnz ... -> decrypting
        rt.asm.jnz(epilogue).unwrap();

        // mov [r12], 0x0 -> release current
        rt.asm.mov(byte_ptr(rdx), 0x0).unwrap();
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
