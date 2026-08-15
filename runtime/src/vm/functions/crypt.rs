use iced_x86::code_asm::{byte_ptr, ptr, r12, r13, r14, r15, rax, rbx, rcx, rdx, word_ptr};

use crate::{
    runtime::{DataDef, FnDef, Runtime},
    vm::{
        bytecode::VMReg,
        utils::{self},
    },
};

// void (bool)
pub fn build(rt: &mut Runtime) {
    let mut check_key = rt.asm.create_label();

    let mut derive_key = rt.asm.create_label();
    let mut start_key = rt.asm.create_label();
    let mut crypt_loop = rt.asm.create_label();
    let mut continue_loop = rt.asm.create_label();
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

    // mov rbx, [r12 + ...]
    utils::vreg::load_reg(rt, r12, VMReg::VBlock, rbx);
    // add rbx, 0x2
    rt.asm.add(rbx, 0x2).unwrap();

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
    // NOTE: TEMPORARY
    rt.asm.jz(epilogue).unwrap();
    // jnz ...
    rt.asm.jnz(check_key).unwrap();

    // ENCRYPTION
    // {
    // }

    // DECRYPTION
    {
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
            rt.asm.je(crypt_loop).unwrap();

            // Release lock on the previous block:
            // mov [r14 - 0x1], 0x0
            rt.asm.mov(byte_ptr(r14 - 0x1), 0x0).unwrap();

            // jmp ...
            rt.asm.jmp(crypt_loop).unwrap();
        }

        rt.asm.set_label(&mut start_key).unwrap();
        {
            // mov rcx, [...]
            rt.asm
                .mov(rcx, ptr(rt.data_labels[&DataDef::VmKeySeed]))
                .unwrap();
        }
    }

    rt.asm.set_label(&mut crypt_loop).unwrap();
    {
        // cmp rbx, r15
        rt.asm.cmp(rbx, r15).unwrap();
        // je ...
        rt.asm.je(epilogue).unwrap();

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
