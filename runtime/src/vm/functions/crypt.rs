use iced_x86::code_asm::{al, byte_ptr, eax, ptr, r12, r13, r14, r15, r8b, rax, rcx, rdx};

use crate::{
    runtime::{DataDef, Runtime},
    vm::{
        bytecode::VMReg,
        utils::{self, stack},
    },
};

// void (unsigned char*, unsigned long, bool)
pub fn build(rt: &mut Runtime) {
    let mut decrypting = rt.asm.create_label();
    let mut spin_previous = rt.asm.create_label();
    let mut acquire_previous = rt.asm.create_label();
    let mut spin_current = rt.asm.create_label();
    let mut acquire_current = rt.asm.create_label();
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

    // mov eax, [...]
    rt.asm
        .mov(eax, ptr(rt.data_labels[&DataDef::VmRegistersTlsIndex]))
        .unwrap();
    // mov rax, gs:[0x1480 + rax * 8]
    rt.asm.mov(rax, ptr(0x1480 + rax * 8).gs()).unwrap();
    // mov r15, [rax + ...]
    utils::vreg::load_reg(rt, rax, VMReg::VAtt, r15);

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
    // mov r14, r12
    rt.asm.mov(r14, r12).unwrap();
    // sub r14, rax
    rt.asm.sub(r14, rax).unwrap();

    // test r8b, r8b
    rt.asm.test(r8b, r8b).unwrap();
    // jnz ...
    rt.asm.jnz(decrypting).unwrap();

    // mov eax, [...]
    rt.asm
        .mov(eax, ptr(rt.data_labels[&DataDef::VmKeyTlsIndex]))
        .unwrap();
    // mov r13, gs:[0x1480 + rax * 8]
    rt.asm.mov(r13, ptr(0x1480 + rax * 8).gs()).unwrap();
    // jmp ...
    rt.asm.jmp(crypt_loop).unwrap();

    rt.asm.set_label(&mut decrypting).unwrap();
    {
        // Check if this is the first block:
        // test r14, r14
        rt.asm.test(r14, r14).unwrap();
        // jz ...
        rt.asm.jz(start_key).unwrap();

        rt.asm.set_label(&mut spin_previous).unwrap();
        {
            // cmp byte [r12 - 0x1], 0x0
            rt.asm.cmp(byte_ptr(r12 - 0x1), 0x0).unwrap();
            // pause
            rt.asm.pause().unwrap();
            // jne ...
            rt.asm.jne(spin_previous).unwrap();
        }

        rt.asm.set_label(&mut acquire_previous).unwrap();
        {
            // mov al, 0x1
            rt.asm.mov(al, 0x1).unwrap();
            // xchg [r12 - 0x1], al
            rt.asm.xchg(ptr(r12 - 0x1), al).unwrap();
            // test al, al
            rt.asm.test(al, al).unwrap();
            // jnz ...
            rt.asm.jnz(spin_previous).unwrap();
        }
    }

    rt.asm.set_label(&mut derive_key).unwrap();
    {
        // mov r13, [r12 - 0x8]
        rt.asm.mov(r13, ptr(r12 - 0x8)).unwrap();
        // mov rax, 0x00FFFFFFFFFFFFFF
        rt.asm.mov(rax, 0x00FFFFFFFFFFFFFFu64).unwrap();
        // and r13, rax
        rt.asm.and(r13, rax).unwrap();
        // xor r13, r15
        rt.asm.xor(r13, r15).unwrap();

        // Release lock on the previous block:
        // mov [r12 - 0x1], 0x0
        rt.asm.mov(byte_ptr(r12 - 0x1), 0x0).unwrap();

        // jmp ...
        rt.asm.jmp(save_key).unwrap();
    }

    rt.asm.set_label(&mut start_key).unwrap();
    {
        // mov r13, [...]
        rt.asm
            .mov(r13, ptr(rt.data_labels[&DataDef::VmKeySeed]))
            .unwrap();
    }

    rt.asm.set_label(&mut save_key).unwrap();
    {
        // mov eax, [...]
        rt.asm
            .mov(eax, ptr(rt.data_labels[&DataDef::VmKeyTlsIndex]))
            .unwrap();
        // mov gs:[0x1480 + rax * 8], r13
        rt.asm.mov(ptr(0x1480 + rax * 8).gs(), r13).unwrap();
    }

    rt.asm.set_label(&mut spin_current).unwrap();
    {
        // cmp [rdx], 0x0
        rt.asm.cmp(byte_ptr(rdx), 0x0).unwrap();
        // pause
        rt.asm.pause().unwrap();
        // jne ...
        rt.asm.jne(spin_current).unwrap();
    }

    rt.asm.set_label(&mut acquire_current).unwrap();
    {
        // mov al, 0x1
        rt.asm.mov(al, 0x1).unwrap();
        // xchg [rdx], al
        rt.asm.xchg(byte_ptr(rdx), al).unwrap();
        // test al, al
        rt.asm.test(al, al).unwrap();
        // jnz ...
        rt.asm.jnz(spin_current).unwrap();
    }

    rt.asm.set_label(&mut crypt_loop).unwrap();
    {
        // cmp rcx, rdx
        rt.asm.cmp(rcx, rdx).unwrap();
        // je ...
        rt.asm.je(unlock).unwrap();

        // mov rax, [rcx]
        rt.asm.mov(rax, ptr(rcx)).unwrap();
        // xor [rcx], r13
        rt.asm.xor(ptr(rcx), r13).unwrap();

        // Skip reading the ciphertext if decrypting since the block was already ciphertext:
        // test r8b, r8b
        rt.asm.test(r8b, r8b).unwrap();
        // jnz ...
        rt.asm.jnz(continue_loop).unwrap();

        // mov rax, [rcx]
        rt.asm.mov(rax, ptr(rcx)).unwrap();

        rt.asm.set_label(&mut continue_loop).unwrap();
        {
            // xor r13, rax
            rt.asm.xor(r13, rax).unwrap();

            // mov rax, [...]
            rt.asm
                .mov(rax, ptr(rt.data_labels[&DataDef::VmKeyMul]))
                .unwrap();
            // imul r13, rax
            rt.asm.imul_2(r13, rax).unwrap();
            // mov rax, [...]
            rt.asm
                .mov(rax, ptr(rt.data_labels[&DataDef::VmKeyAdd]))
                .unwrap();
            // add r13, rax
            rt.asm.add(r13, rax).unwrap();

            // add rcx, 0x8
            rt.asm.add(rcx, 0x8).unwrap();
            // jmp ...
            rt.asm.jmp(crypt_loop).unwrap();
        }
    }

    rt.asm.set_label(&mut unlock).unwrap();
    {
        // test r8b, r8b
        rt.asm.test(r8b, r8b).unwrap();
        // jnz ...
        rt.asm.jnz(epilogue).unwrap();

        // If encrypting release lock on the current block:
        // mov [r12], 0x0
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
