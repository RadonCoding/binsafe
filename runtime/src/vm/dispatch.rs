use iced_x86::code_asm::{byte_ptr, ptr, r12, r13, r14, r8, r9b, rax, rcx, rdx, word_ptr};

use crate::{
    runtime::{DataDef, FnDef, Runtime},
    vm::{bytecode::VMReg, stack, utils},
};

// void (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut execute_loop = rt.asm.create_label();
    let mut check_branch = rt.asm.create_label();
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

    // mov [r12 + ...], r13
    utils::mov_vreg_reg_64(rt, r12, r13, VMReg::Vbp);

    // movzx rax, [r13]
    rt.asm.movzx(rax, word_ptr(r13)).unwrap();
    // add r13, 0x2
    rt.asm.add(r13, 0x2).unwrap();

    // mov [r12 + ...], rax
    utils::mov_vreg_reg_64(rt, r12, rax, VMReg::Vbl);

    // lea r14, [r13 + rax]
    rt.asm.lea(r14, ptr(r13 + rax)).unwrap();

    // mov rcx, [r14 + ...]
    utils::mov_reg_vreg_64(rt, r12, VMReg::Vbp, rcx);
    // mov rdx, [r14 + ...]
    utils::mov_reg_vreg_64(rt, r12, VMReg::Vbl, rdx);
    // mov r8, [r14 + ...]
    utils::mov_reg_vreg_64(rt, r12, VMReg::Vsk, r8);
    // mov r9b, 0x1
    rt.asm.mov(r9b, 0x1).unwrap();

    #[cfg(debug_assertions)]
    {
        utils::start_profiling(rt, "DECRYPT");

        // call ...
        stack::call(rt, rt.func_labels[&FnDef::VmCrypt]);

        utils::stop_profiling(rt, "DECRYPT");
    }
    #[cfg(not(debug_assertions))]
    // call ...
    stack::call_with_label(rt, rt.func_labels[&FnDef::VmCrypt], &execute_loop);

    rt.asm.set_label(&mut execute_loop).unwrap();
    {
        // cmp r13, r14
        rt.asm.cmp(r13, r14).unwrap();
        // je ...
        rt.asm.je(check_branch).unwrap();

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

        // jmp ...
        rt.asm.jmp(execute_loop).unwrap();
    }

    rt.asm.set_label(&mut check_branch).unwrap();
    {
        // mov rax, [...]
        utils::mov_reg_vreg_64(rt, r12, VMReg::Ven, rax);
        // cmp [...],
        utils::cmp_vreg_reg_64(rt, r12, VMReg::Vbr, rax);
        // jne ...
        rt.asm.jne(epilogue).unwrap();

        // mov r13, [...]
        utils::mov_reg_vreg_64(rt, r12, VMReg::Vbp, r13);
        // jmp ...
        rt.asm.jmp(execute_loop).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rcx, [r14 + ...]
        utils::mov_reg_vreg_64(rt, r12, VMReg::Vbp, rcx);
        // mov rdx, [r14 + ...]
        utils::mov_reg_vreg_64(rt, r12, VMReg::Vbl, rdx);
        // mov r8, [r14 + ...]
        utils::mov_reg_vreg_64(rt, r12, VMReg::Vsk, r8);
        // xor r9b, r9b
        rt.asm.xor(r9b, r9b).unwrap();
        // call ...
        stack::call(rt, rt.func_labels[&FnDef::VmCrypt]);

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
