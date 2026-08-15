use iced_x86::code_asm::{
    al, byte_ptr, cl, eax, ecx, ptr, qword_ptr, r12, r13, r14, r15, rax, rbx, rcx, rdx, word_ptr,
};

use crate::{
    runtime::{DataDef, FnDef, Runtime},
    vm::{
        bytecode::VMReg,
        utils::{self},
    },
};

// void (bool)
pub fn build(rt: &mut Runtime) {
    let mut spin_current_decrypt = rt.asm.create_label();
    let mut acquire_current_decrypt = rt.asm.create_label();

    let mut spin_current_encrypt = rt.asm.create_label();
    let mut acquire_current_encrypt = rt.asm.create_label();

    let mut check_key = rt.asm.create_label();

    let mut spin_previous = rt.asm.create_label();
    let mut acquire_previous = rt.asm.create_label();

    let mut derive_key = rt.asm.create_label();
    let mut start_key = rt.asm.create_label();
    let mut save_key = rt.asm.create_label();
    let mut crypt_loop = rt.asm.create_label();
    let mut continue_loop = rt.asm.create_label();
    let mut unlock = rt.asm.create_label();
    let mut finish_encrypt = rt.asm.create_label();
    let mut finish_decrypt = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();
    // push r15
    rt.asm.push(r15).unwrap();
    // push rbx
    rt.asm.push(rbx).unwrap();

    // mov r13, rcx
    rt.asm.mov(r13, rcx).unwrap();

    // mov r14, [r12 + ...]
    utils::vreg::load_reg(rt, r12, VMReg::BPointer, r14);
    // mov r15, [r12 + ...]
    utils::vreg::load_reg(rt, r12, VMReg::BLength, r15);

    // lea rbx, [r14 + 0x2]
    rt.asm.lea(rbx, ptr(r14 + 0x2)).unwrap();

    // +8 for integrity +7 for alignment:
    // add r15, 0x8 + 0x7
    rt.asm.add(r15, 0x8 + 0x7).unwrap();
    // and r15, -0x8
    rt.asm.and(r15, -0x8).unwrap();
    // add r15, rbx
    rt.asm.add(r15, rbx).unwrap();

    // Skip blocks that are decrypted but not locked (state=1) (lock=0):
    // cmp [r15], 0x0001
    rt.asm.cmp(word_ptr(r15), 0x0001).unwrap();
    // je ...
    rt.asm.je(epilogue).unwrap();

    // test r13, r13
    rt.asm.test(r13, r13).unwrap();
    // jnz ...
    rt.asm.jnz(spin_current_decrypt).unwrap();

    // ENCRYPTION
    {
        // mov ecx, [...]
        rt.asm
            .mov(ecx, ptr(rt.data_labels[&DataDef::VmKeyTlsIndex]))
            .unwrap();
        // cmp gs:[0x1480 + rcx * 8], 0x0
        rt.asm.cmp(qword_ptr(0x1480 + rcx * 8).gs(), 0x0).unwrap();
        // jne ...
        rt.asm.jne(spin_current_encrypt).unwrap();

        // lock dec [r15 + 0x1]
        rt.asm.lock().dec(byte_ptr(r15 + 0x1)).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();

        rt.asm.set_label(&mut spin_current_encrypt).unwrap();
        {
            // cmp [r15 + 0x1], 0x1
            rt.asm.cmp(byte_ptr(r15 + 0x1), 0x1).unwrap();
            // pause
            rt.asm.pause().unwrap();
            // jne ...
            rt.asm.jne(spin_current_encrypt).unwrap();
        }

        rt.asm.set_label(&mut acquire_current_encrypt).unwrap();
        {
            // mov al, 0x1
            rt.asm.mov(al, 0x1).unwrap();
            // mov cl, 0xff
            rt.asm.mov(cl, 0xff).unwrap();
            // lock cmpxchg [r15 + 0x1], cl
            rt.asm.lock().cmpxchg(byte_ptr(r15 + 0x1), cl).unwrap();
            // jne ...
            rt.asm.jne(spin_current_encrypt).unwrap();
        }

        // mov ecx, [...]
        rt.asm
            .mov(ecx, ptr(rt.data_labels[&DataDef::VmKeyTlsIndex]))
            .unwrap();
        // mov rcx, gs:[0x1480 + rcx * 8]
        rt.asm.mov(rcx, ptr(0x1480 + rcx * 8).gs()).unwrap();

        // jmp ...
        rt.asm.jmp(crypt_loop).unwrap();
    }

    // DECRYPTION
    {
        rt.asm.set_label(&mut spin_current_decrypt).unwrap();
        {
            // cmp [r15 + 0x1], 0xff
            rt.asm.cmp(byte_ptr(r15 + 0x1), 0xff).unwrap();
            // pause
            rt.asm.pause().unwrap();
            // je ...
            rt.asm.je(spin_current_decrypt).unwrap();
        }

        rt.asm.set_label(&mut acquire_current_decrypt).unwrap();
        {
            // mov al, 0x00
            rt.asm.mov(al, 0x00).unwrap();
            // mov cl, 0xff
            rt.asm.mov(cl, 0xff).unwrap();
            // lock cmpxchg [r15 + 0x1], cl
            rt.asm.lock().cmpxchg(byte_ptr(r15 + 0x1), cl).unwrap();

            // je ...
            rt.asm.je(check_key).unwrap();

            // cmp al, 0xff
            rt.asm.cmp(al, 0xff).unwrap();
            // je ...
            rt.asm.je(spin_current_decrypt).unwrap();

            // mov cl, al
            rt.asm.mov(cl, al).unwrap();
            // inc cl
            rt.asm.inc(cl).unwrap();
            // lock cmpxchg [r15 + 0x1], cl
            rt.asm.lock().cmpxchg(byte_ptr(r15 + 0x1), cl).unwrap();

            // jne ...
            rt.asm.jne(spin_current_decrypt).unwrap();

            // jmp ...
            rt.asm.jmp(epilogue).unwrap();
        }

        rt.asm.set_label(&mut check_key).unwrap();
        {
            // lea rax, [...]
            rt.asm
                .lea(rax, ptr(rt.data_labels[&DataDef::VmCode]))
                .unwrap();
            // movsxd rcx, [rax]
            rt.asm.movsxd(rcx, ptr(rax)).unwrap();
            // add rax, rcx
            rt.asm.add(rax, rcx).unwrap();
            // cmp r14, rax
            rt.asm.cmp(r14, rax).unwrap();
            // je ...
            rt.asm.je(start_key).unwrap();

            // Skip blocks that are decrypted but not locked (state=1) (lock=0):
            // cmp [r14 - 0x2], 0x0001
            rt.asm.cmp(word_ptr(r14 - 0x2), 0x0001).unwrap();
            // je ...
            rt.asm.je(derive_key).unwrap();
        }

        rt.asm.set_label(&mut spin_previous).unwrap();
        {
            // cmp byte [r14 - 0x1], 0x0
            rt.asm.cmp(byte_ptr(r14 - 0x1), 0x0).unwrap();
            // pause
            rt.asm.pause().unwrap();
            // jne ...
            rt.asm.jne(spin_previous).unwrap();
        }

        rt.asm.set_label(&mut acquire_previous).unwrap();
        {
            // mov al, 0x00
            rt.asm.mov(al, 0x00).unwrap();
            // mov cl, 0xff
            rt.asm.mov(cl, 0xff).unwrap();
            // lock cmpxchg [r14 - 0x1], cl
            rt.asm.lock().cmpxchg(byte_ptr(r14 - 0x1), cl).unwrap();
            // jne ...
            rt.asm.jne(spin_previous).unwrap();
        }

        rt.asm.set_label(&mut derive_key).unwrap();
        {
            // lea rcx, [...]
            rt.asm
                .lea(rcx, ptr(rt.data_labels[&DataDef::VmCode]))
                .unwrap();
            // movsxd rax, [rcx]
            rt.asm.movsxd(rax, ptr(rcx)).unwrap();
            // add rcx, rax
            rt.asm.add(rcx, rax).unwrap();
            // mov rdx, r14
            rt.asm.mov(rdx, r14).unwrap();
            // call ...
            rt.asm.call(rt.function_labels[&FnDef::VmInvoke]).unwrap();

            // mov rcx, rax
            rt.asm.mov(rcx, rax).unwrap();

            // cmp [r14 - 0x2], 0x0001
            rt.asm.cmp(word_ptr(r14 - 0x2), 0x0001).unwrap();
            // je ...
            rt.asm.je(save_key).unwrap();

            // Release lock on the previous block:
            // mov [r14 - 0x1], 0x0
            rt.asm.mov(byte_ptr(r14 - 0x1), 0x0).unwrap();

            // jmp ...
            rt.asm.jmp(save_key).unwrap();
        }

        rt.asm.set_label(&mut start_key).unwrap();
        {
            // mov rcx, [...]
            rt.asm
                .mov(rcx, ptr(rt.data_labels[&DataDef::VmKeySeed]))
                .unwrap();
        }

        rt.asm.set_label(&mut save_key).unwrap();
        {
            // mov eax, [...]
            rt.asm
                .mov(eax, ptr(rt.data_labels[&DataDef::VmKeyTlsIndex]))
                .unwrap();
            // mov gs:[0x1480 + rax * 8], rcx
            rt.asm.mov(ptr(0x1480 + rax * 8).gs(), rcx).unwrap();
        }
    }

    rt.asm.set_label(&mut crypt_loop).unwrap();
    {
        // cmp rbx, r15
        rt.asm.cmp(rbx, r15).unwrap();
        // je ...
        rt.asm.je(unlock).unwrap();

        // mov rax, [rbx]
        rt.asm.mov(rax, ptr(rbx)).unwrap();
        // xor [rbx], rcx
        rt.asm.xor(ptr(rbx), rcx).unwrap();

        // test r13, r13
        rt.asm.test(r13, r13).unwrap();
        // jnz ...
        rt.asm.jnz(continue_loop).unwrap();

        // mov rax, [rbx]
        rt.asm.mov(rax, ptr(rbx)).unwrap();

        rt.asm.set_label(&mut continue_loop).unwrap();
        {
            // xor rcx, rax
            rt.asm.xor(rcx, rax).unwrap();

            // mov rax, [...]
            rt.asm
                .mov(rax, ptr(rt.data_labels[&DataDef::VmKeyMul]))
                .unwrap();
            // imul rcx, rax
            rt.asm.imul_2(rcx, rax).unwrap();
            // mov rax, [...]
            rt.asm
                .mov(rax, ptr(rt.data_labels[&DataDef::VmKeyAdd]))
                .unwrap();
            // add rcx, rax
            rt.asm.add(rcx, rax).unwrap();

            // add rbx, 0x8
            rt.asm.add(rbx, 0x8).unwrap();
            // jmp ...
            rt.asm.jmp(crypt_loop).unwrap();
        }
    }

    rt.asm.set_label(&mut unlock).unwrap();
    {
        // test r13, r13
        rt.asm.test(r13, r13).unwrap();
        // jnz ...
        rt.asm.jnz(finish_decrypt).unwrap();
    }

    rt.asm.set_label(&mut finish_encrypt).unwrap();
    {
        // Release reference on the current block and mark as encrypted:
        // mov [r15], 0x0
        rt.asm.mov(word_ptr(r15), 0x0).unwrap();

        // mov ecx, [...]
        rt.asm
            .mov(ecx, ptr(rt.data_labels[&DataDef::VmKeyTlsIndex]))
            .unwrap();
        // mov gs:[0x1480 + rcx * 8], 0x0
        rt.asm.mov(qword_ptr(0x1480 + rcx * 8).gs(), 0x0).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut finish_decrypt).unwrap();
    {
        // Acquire reference on the current block and mark as decrypted:
        // mov [r15], 0x0101
        rt.asm.mov(word_ptr(r15), 0x0101).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // pop rbx
        rt.asm.pop(rbx).unwrap();
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
