use iced_x86::code_asm::{byte_ptr, ptr, r12, r13, r14, r8, r8b, rax, rcx, rdx};

use crate::{
    runtime::{DataDef, FnDef, Runtime},
    vm::{
        bytecode::{VMOp, VMReg},
        stack, utils,
    },
};

// void (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut execute_loop = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

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

    // mov r14, [r12 + ...]
    utils::mov_reg_vreg_64(rt, r12, VMReg::Rip, r14);

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
        (VMOp::SetMemReg, FnDef::VmHandlerSetMemReg),
        (VMOp::SetMemImm, FnDef::VmHandlerSetMemImm),
        (VMOp::AddSubRegImm, FnDef::VmHandlerAddSubRegImm),
        (VMOp::AddSubRegReg, FnDef::VmHandlerAddSubRegReg),
        (VMOp::AddSubMemImm, FnDef::VmHandlerAddSubMemImm),
        (VMOp::AddSubMemReg, FnDef::VmHandlerAddSubMemReg),
        (VMOp::BranchRel, FnDef::VmHandlerBranchRel),
        (VMOp::BranchReg, FnDef::VmHandlerBranchReg),
        (VMOp::BranchMem, FnDef::VmHandlerBranchMem),
        (VMOp::Jcc, FnDef::VmHandlerJcc),
        (VMOp::Nop, FnDef::VmHandlerNop),
    ];

    for (op, func) in table {
        // lea rcx, [...]
        rt.asm.lea(rcx, ptr(rt.func_labels[&func])).unwrap();
        // mov [rax + ...], rcx
        rt.asm.mov(ptr(rax + (op as u8 - 1) * 8), rcx).unwrap();
    }

    rt.asm.set_label(&mut execute_loop).unwrap();
    {
        // movzx r8, [r13] -> op
        rt.asm.movzx(r8, byte_ptr(r13)).unwrap();
        // add r13, 0x1
        rt.asm.add(r13, 0x1).unwrap();

        // test r8b, r8b
        rt.asm.test(r8b, r8b).unwrap();
        // jz ...
        rt.asm.jz(epilogue).unwrap();

        // dec r8b
        rt.asm.dec(r8b).unwrap();

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
        utils::cmp_vreg_reg_64(rt, r12, VMReg::Rip, r14);
        // jne ...
        rt.asm.jne(epilogue).unwrap();

        // jmp ...
        rt.asm.jmp(execute_loop).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
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
