use iced_x86::code_asm::{al, byte_ptr, eax, ptr, r12, r13, r14, r15, r8, r9, rax, rcx, rdx};

use crate::{
    runtime::{DataDef, Runtime},
    vm::{
        bytecode::VMReg,
        utils::{self},
    },
};

// void (bool)
pub fn build(rt:  &mut Runtime) {
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

    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();
    // push r15
    rt.asm.push(r15).unwrap();

    // mov r13, [r12 + ...]
    utils::vreg::load_reg(rt, r12, VMReg::BPointer, r13);
    // mov r14, [r12 + ...]
    utils::vreg::load_reg(rt, r12, VMReg::BLength, r14);
    // mov r15, [r12 + ...]
    utils::vreg::load_reg(rt, r12, VMReg::VAtt, r15);

    // lea r8, [r13 + 0x2]
    rt.asm.lea(r8, ptr(r13 + 0x2)).unwrap();

    // add r14, 0x7
    rt.asm.add(r14, 0x7).unwrap();
    // and r14, -0x8
    rt.asm.and(r14, -0x8).unwrap();
    // add r14, r8
    rt.asm.add(r14, r8).unwrap();

    // lea rax, [...]
    rt.asm
        .lea(rax, ptr(rt.data_labels[&DataDef::VmCode]))
        .unwrap();
    // mov rdx, r13
    rt.asm.mov(rdx, r13).unwrap();
    // sub rdx, rax
    rt.asm.sub(rdx, rax).unwrap();

    // test rcx, rcx
    rt.asm.test(rcx, rcx).unwrap();
    // jnz ...
    rt.asm.jnz(decrypting).unwrap();

    // mov eax, [...]
    rt.asm
        .mov(eax, ptr(rt.data_labels[&DataDef::VmKeyTlsIndex]))
        .unwrap();
    // mov r9, gs:[0x1480 + rax * 8]
    rt.asm.mov(r9, ptr(0x1480 + rax * 8).gs()).unwrap();
    // jmp ...
    rt.asm.jmp(crypt_loop).unwrap();

    rt.asm.set_label(&mut decrypting).unwrap();
    {
        // test rdx, rdx
        rt.asm.test(rdx, rdx).unwrap();
        // jz ...
        rt.asm.jz(start_key).unwrap();

        rt.asm.set_label(&mut spin_previous).unwrap();
        {
            // cmp byte [r13 - 0x1], 0x0
            rt.asm.cmp(byte_ptr(r13 - 0x1), 0x0).unwrap();
            // pause
            rt.asm.pause().unwrap();
            // jne ...
            rt.asm.jne(spin_previous).unwrap();
        }

        rt.asm.set_label(&mut acquire_previous).unwrap();
        {
            // mov al, 0x1
            rt.asm.mov(al, 0x1).unwrap();
            // xchg [r13 - 0x1], al
            rt.asm.xchg(ptr(r13 - 0x1), al).unwrap();
            // test al, al
            rt.asm.test(al, al).unwrap();
            // jnz ...
            rt.asm.jnz(spin_previous).unwrap();
        }
    }

    rt.asm.set_label(&mut derive_key).unwrap();
    {
        // mov r9, [r13 - 0x8]
        rt.asm.mov(r9, ptr(r13 - 0x8)).unwrap();
        // mov rax, 0x00FFFFFFFFFFFFFF
        rt.asm.mov(rax, 0x00FFFFFFFFFFFFFFu64).unwrap();
        // and r9, rax
        rt.asm.and(r9, rax).unwrap();
        // xor r9, r15
        rt.asm.xor(r9, r15).unwrap();

        // Release lock on the previous block:
        // mov [r13 - 0x1], 0x0
        rt.asm.mov(byte_ptr(r13 - 0x1), 0x0).unwrap();

        // jmp ...
        rt.asm.jmp(save_key).unwrap();
    }

    rt.asm.set_label(&mut start_key).unwrap();
    {
        // mov r9, [...]
        rt.asm
            .mov(r9, ptr(rt.data_labels[&DataDef::VmKeySeed]))
            .unwrap();
    }

    rt.asm.set_label(&mut save_key).unwrap();
    {
        // mov eax, [...]
        rt.asm
            .mov(eax, ptr(rt.data_labels[&DataDef::VmKeyTlsIndex]))
            .unwrap();
        // mov gs:[0x1480 + rax * 8], r9
        rt.asm.mov(ptr(0x1480 + rax * 8).gs(), r9).unwrap();
    }

    rt.asm.set_label(&mut spin_current).unwrap();
    {
        // cmp [r14], 0x0
        rt.asm.cmp(byte_ptr(r14), 0x0).unwrap();
        // pause
        rt.asm.pause().unwrap();
        // jne ...
        rt.asm.jne(spin_current).unwrap();
    }

    rt.asm.set_label(&mut acquire_current).unwrap();
    {
        // mov al, 0x1
        rt.asm.mov(al, 0x1).unwrap();
        // xchg [r14], al
        rt.asm.xchg(byte_ptr(r14), al).unwrap();
        // test al, al
        rt.asm.test(al, al).unwrap();
        // jnz ...
        rt.asm.jnz(spin_current).unwrap();
    }

    rt.asm.set_label(&mut crypt_loop).unwrap();
    {
        // cmp r8, r14
        rt.asm.cmp(r8, r14).unwrap();
        // je ...
        rt.asm.je(unlock).unwrap();

        // mov rax, [r8]
        rt.asm.mov(rax, ptr(r8)).unwrap();
        // xor [r8], r9
        rt.asm.xor(ptr(r8), r9).unwrap();

        // Skip reading the ciphertext if decrypting since the block was already ciphertext:
        // test rcx, rcx
        rt.asm.test(rcx, rcx).unwrap();
        // jnz ...
        rt.asm.jnz(continue_loop).unwrap();

        // mov rax, [r8]
        rt.asm.mov(rax, ptr(r8)).unwrap();

        rt.asm.set_label(&mut continue_loop).unwrap();
        {
            // xor r9, rax
            rt.asm.xor(r9, rax).unwrap();

            // mov rax, [...]
            rt.asm
                .mov(rax, ptr(rt.data_labels[&DataDef::VmKeyMul]))
                .unwrap();
            // imul r9, rax
            rt.asm.imul_2(r9, rax).unwrap();
            // mov rax, [...]
            rt.asm
                .mov(rax, ptr(rt.data_labels[&DataDef::VmKeyAdd]))
                .unwrap();
            // add r9, rax
            rt.asm.add(r9, rax).unwrap();

            // add r8, 0x8
            rt.asm.add(r8, 0x8).unwrap();
            // jmp ...
            rt.asm.jmp(crypt_loop).unwrap();
        }
    }

    rt.asm.set_label(&mut unlock).unwrap();
    {
        // test rcx, rcx
        rt.asm.test(rcx, rcx).unwrap();
        // jnz ...
        rt.asm.jnz(epilogue).unwrap();

        // If encrypting release lock on the current block:
        // mov [r14], 0x0
        rt.asm.mov(byte_ptr(r14), 0x0).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // pop r15
        rt.asm.pop(r15).unwrap();
        // pop r14
        rt.asm.pop(r14).unwrap();
        // pop r13
        rt.asm.pop(r13).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
