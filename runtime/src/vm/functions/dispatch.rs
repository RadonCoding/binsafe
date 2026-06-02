use iced_x86::code_asm::{
    byte_ptr, eax, ecx, edx, ptr, r12, r13, r14, r8, r8b, r8d, rax, rcx, rdx,
};

use crate::{
    runtime::{DataDef, FnDef, Runtime},
    vm::{
        bytecode::VMReg,
        utils::{self, stack},
    },
    VM_DISPATCH_SIZE,
};

// void (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut setup_block = rt.asm.create_label();
    let mut start_block = rt.asm.create_label();
    let mut execute_loop = rt.asm.create_label();
    let mut check_branch = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();
    let mut exit = rt.asm.create_label();

    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);
    // push r14
    stack::push(rt, r14);

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();
    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    rt.asm.set_label(&mut setup_block).unwrap();
    {
        // Initialize block pointer and block length:
        // mov [r12 + ...], r13
        utils::vreg::store_reg(rt, r12, r13, VMReg::BPointer);
        // movzx rax, [r13]; add r13, 0x2
        utils::bytecode::read_word_zx(rt, r13, eax);
        // mov [r12 + ...], rax
        utils::vreg::store_reg(rt, r12, rax, VMReg::BLength);

        // Store the end of the block:
        // lea r14, [r13 + rax]
        rt.asm.lea(r14, ptr(r13 + rax)).unwrap();

        // Decrypt the block:
        // mov rcx, [r12 + ...]
        utils::vreg::load_reg(rt, r12, VMReg::BPointer, rcx);
        // mov rdx, [r12 + ...]
        utils::vreg::load_reg(rt, r12, VMReg::BLength, rdx);
        // mov r8b, 0x1
        rt.asm.mov(r8b, 0x1).unwrap();
        // call ...
        stack::call_with_label(rt, rt.func_labels[&FnDef::VmCrypt], &start_block);
    }

    rt.asm.set_label(&mut start_block).unwrap();
    {
        // mov [r12 + ...], 0x0
        utils::vreg::store_imm(rt, r12, 0x0, VMReg::NBranch);
        // mov [r12 + ...], 0x0
        utils::vreg::store_imm(rt, r12, 0x0, VMReg::VImm);
    }

    rt.asm.set_label(&mut execute_loop).unwrap();
    {
        // cmp r13, r14
        rt.asm.cmp(r13, r14).unwrap();
        // je ...
        rt.asm.je(check_branch).unwrap();

        // r8d -> operation
        utils::bytecode::read_byte_zx(rt, r13, r8d);

        // lea rax, [...]
        rt.asm
            .lea(rax, ptr(rt.data_labels[&DataDef::VmHandlers]))
            .unwrap();
        // mov rax, [rax + r8*8]
        rt.asm.mov(rax, ptr(rax + r8 * 8)).unwrap();

        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // mov rdx, r13
        rt.asm.mov(rdx, r13).unwrap();
        // call rax
        stack::call(rt, rax);

        // mov r13, rax
        rt.asm.mov(r13, rax).unwrap();

        // jmp ...
        rt.asm.jmp(execute_loop).unwrap();
    }

    rt.asm.set_label(&mut check_branch).unwrap();
    {
        // cmp [r12 + ...], 0x0
        utils::vreg::cmp_imm(rt, r12, VMReg::NBranch, 0x0);
        // je ...
        rt.asm.je(epilogue).unwrap();

        // mov rax, [r12 + ...]
        utils::vreg::load_reg(rt, r12, VMReg::NEntry, rax);
        // cmp [r12 + ...],
        utils::vreg::cmp_reg(rt, r12, VMReg::NBranch, rax);
        // jne ...
        rt.asm.jne(epilogue).unwrap();

        // If the branch points to the native entry then re-execute the block:
        // mov r13, [...]
        utils::vreg::load_reg(rt, r12, VMReg::BPointer, r13);
        // jmp ...
        rt.asm.jmp(start_block).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // Re-encrypt the current block:
        // mov rcx, [r12 + ...]
        utils::vreg::load_reg(rt, r12, VMReg::BPointer, rcx);
        // mov rdx, [r12 + ...]
        utils::vreg::load_reg(rt, r12, VMReg::BLength, rdx);
        // xor r8b, r8b
        rt.asm.xor(r8b, r8b).unwrap();
        // call ...
        stack::call(rt, rt.func_labels[&FnDef::VmCrypt]);

        // If the branch points to a dispatch stub then link to that block:
        // cmp [r12 + ...], 0x0
        utils::vreg::cmp_imm(rt, r12, VMReg::NBranch, 0x0);
        // je ...
        rt.asm.je(exit).unwrap();

        // mov rax, [r12 + ...]
        utils::vreg::load_reg(rt, r12, VMReg::NBranch, rax);
        // cmp byte [rax], 0x68
        rt.asm.cmp(byte_ptr(rax), 0x68).unwrap();
        // jne ...
        rt.asm.jne(exit).unwrap();

        // mov ecx, [rax + 0x1]
        rt.asm.mov(ecx, ptr(rax + 0x1)).unwrap();

        // add rax, ...
        rt.asm.add(rax, VM_DISPATCH_SIZE as i32).unwrap();

        // mov rdx, rax
        rt.asm.mov(rdx, rax).unwrap();
        // sub rdx, [r12 + ...]
        utils::vreg::reg_sub(rt, r12, VMReg::VImage, rdx);

        // xor ecx, edx
        rt.asm.xor(ecx, edx).unwrap();
        // and ecx, 0x0FFFFFFF
        rt.asm.and(ecx, 0x0FFFFFFF).unwrap();

        // lea rdx, [...]
        rt.asm
            .lea(rdx, ptr(rt.data_labels[&DataDef::VmTable]))
            .unwrap();
        // mov r8d, [rdx + rcx*8]
        rt.asm.mov(r8d, ptr(rdx + rcx * 8)).unwrap();
        // mov edx, [rdx + rcx*8 + 0x4]
        rt.asm.mov(edx, ptr(rdx + rcx * 8 + 0x4)).unwrap();

        // lea r13, [...]
        rt.asm
            .lea(r13, ptr(rt.data_labels[&DataDef::VmCode]))
            .unwrap();
        // add r13, rdx
        rt.asm.add(r13, rdx).unwrap();

        // Apply the displacement to the native entry and exit points:
        // mov rdx, rax
        rt.asm.mov(rdx, rax).unwrap();
        // add rdx, r8
        rt.asm.add(rdx, r8).unwrap();
        // mov [r12 + ...], rdx
        utils::vreg::store_reg(rt, r12, rdx, VMReg::NExit);

        // mov rdx, rax
        rt.asm.mov(rdx, rax).unwrap();
        // sub rdx, r8
        rt.asm.sub(rdx, r8).unwrap();
        // mov [r12 + ...], rdx
        utils::vreg::store_reg(rt, r12, rdx, VMReg::NEntry);

        // jmp ...
        rt.asm.jmp(setup_block).unwrap();
    }

    rt.asm.set_label(&mut exit).unwrap();
    {
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
