use iced_x86::code_asm::{
    byte_ptr, ptr, r12, r13, r14, r15, r8, r9b, rax, rbx, rcx, rdx, word_ptr,
};

use crate::{
    runtime::{DataDef, FnDef, Runtime},
    vm::{
        bytecode::{VMOp, VMReg},
        stack, utils,
    },
};

// void (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut initialize_key = rt.asm.create_label();
    let mut decrypt_block = rt.asm.create_label();
    let mut execute_loop = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);
    // push r14
    stack::push(rt, r14);
    // push r15
    stack::push(rt, r15);
    // push rbx
    stack::push(rt, rbx);

    // mov r12, rcx
    rt.asm.mov(r12, rcx).unwrap();
    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // mov r14, [r12 + ...]
    utils::mov_reg_vreg_64(rt, r12, VMReg::Vip, r14);

    // mov rbx, r13
    rt.asm.mov(rbx, r13).unwrap();
    // add r13, 0x2
    rt.asm.add(r13, 0x2).unwrap();

    // lea rax, [...]
    rt.asm
        .lea(rax, ptr(rt.data_labels[&DataDef::VmCode]))
        .unwrap();
    // cmp rbx, rax
    rt.asm.cmp(rbx, rax).unwrap();
    // jne ...
    rt.asm.jne(initialize_key).unwrap();

    // xor r15, r15
    rt.asm.xor(r15, r15).unwrap();
    // jmp ...
    rt.asm.jmp(decrypt_block).unwrap();

    rt.asm.set_label(&mut initialize_key).unwrap();
    {
        // movzx r15, [rbx - 0x1]
        rt.asm.movzx(r15, byte_ptr(rbx - 0x1)).unwrap();
    }

    rt.asm.set_label(&mut decrypt_block).unwrap();
    {
        // mov rcx, r15
        rt.asm.mov(rcx, r15).unwrap();
        // mov rdx, rbx
        rt.asm.mov(rdx, rbx).unwrap();
        // add rdx, 0x2
        rt.asm.add(rdx, 0x2).unwrap();
        // movzx r8, [rbx] -> length
        rt.asm.movzx(r8, word_ptr(rbx)).unwrap();
        // mov r9b, 0x1
        rt.asm.mov(r9b, 0x1u32).unwrap();
        // call ...
        stack::call(rt, rt.func_labels[&FnDef::VmCrypt]);
    }

    // lea rax, [...]
    rt.asm
        .lea(rax, ptr(rt.data_labels[&DataDef::VmHandlers]))
        .unwrap();
    // mov rcx, [rax]
    rt.asm.mov(rcx, ptr(rax)).unwrap();
    // test rcx, rcx
    rt.asm.test(rcx, rcx).unwrap();
    // jnz ...
    rt.asm.jnz(execute_loop).unwrap();

    let table = [
        (VMOp::PushImm, FnDef::VmHandlerPushImm),
        (VMOp::PushReg64, FnDef::VmHandlerPushReg64),
        (VMOp::PopReg64, FnDef::VmHandlerPopReg64),
        (VMOp::SetRegImm, FnDef::VmHandlerSetRegImm),
        (VMOp::SetRegReg, FnDef::VmHandlerSetRegReg),
        (VMOp::SetRegMem, FnDef::VmHandlerSetRegMem),
        (VMOp::SetMemImm, FnDef::VmHandlerSetMemImm),
        (VMOp::SetMemReg, FnDef::VmHandlerSetMemReg),
        (VMOp::AddSubRegImm, FnDef::VmHandlerAddSubRegImm),
        (VMOp::AddSubRegReg, FnDef::VmHandlerAddSubRegReg),
        (VMOp::AddSubRegMem, FnDef::VmHandlerAddSubRegMem),
        (VMOp::AddSubMemImm, FnDef::VmHandlerAddSubMemImm),
        (VMOp::AddSubMemReg, FnDef::VmHandlerAddSubMemReg),
        (VMOp::BranchImm, FnDef::VmHandlerBranchImm),
        (VMOp::BranchReg, FnDef::VmHandlerBranchReg),
        (VMOp::BranchMem, FnDef::VmHandlerBranchMem),
        (VMOp::Jcc, FnDef::VmHandlerJcc),
        (VMOp::Nop, FnDef::VmHandlerNop),
    ];

    for (op, func) in table {
        // lea rcx, [...]
        rt.asm.lea(rcx, ptr(rt.func_labels[&func])).unwrap();
        // mov [rax + ...], rcx
        rt.asm.mov(ptr(rax + rt.mapper.index(op) * 8), rcx).unwrap();
    }

    rt.asm.set_label(&mut execute_loop).unwrap();
    {
        // movzx rax, [rbx] -> length
        rt.asm.movzx(rax, word_ptr(rbx)).unwrap();
        // lea rax, [rbx + rax + 0x2]
        rt.asm.lea(rax, ptr(rbx + rax + 0x2)).unwrap();
        // cmp r13, rax
        rt.asm.cmp(r13, rax).unwrap();
        // jae ...
        rt.asm.jae(epilogue).unwrap();

        // movzx r8, [r13] -> op
        rt.asm.movzx(r8, byte_ptr(r13)).unwrap();
        // add r13, 0x1
        rt.asm.add(r13, 0x1).unwrap();

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

        // cmp [r12 + ...], r14
        utils::cmp_vreg_reg_64(rt, r12, VMReg::Vip, r14);
        // jne ...
        rt.asm.jne(epilogue).unwrap();

        // jmp ...
        rt.asm.jmp(execute_loop).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rcx, r15
        rt.asm.mov(rcx, r15).unwrap();
        // mov rdx, rbx
        rt.asm.mov(rdx, rbx).unwrap();
        // add rdx, 0x2
        rt.asm.add(rdx, 0x2).unwrap();
        // movzx r8, [rbx] -> length
        rt.asm.movzx(r8, word_ptr(rbx)).unwrap();
        // xor r9b, r9b
        rt.asm.xor(r9b, r9b).unwrap();
        // call ...
        stack::call(rt, rt.func_labels[&FnDef::VmCrypt]);

        // pop rbx
        stack::pop(rt, rbx);
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
