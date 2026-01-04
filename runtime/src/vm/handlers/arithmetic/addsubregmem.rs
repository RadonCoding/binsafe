use iced_x86::code_asm::{
    byte_ptr, ptr, r12, r13, r14, r14b, r8, r8b, r8d, r8w, r9, r9b, rax, rcx, rdx,
};

use crate::{
    runtime::{FnDef, Runtime},
    vm::{bytecode::VMBits, stack},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut lower8 = rt.asm.create_label();
    let mut higher8 = rt.asm.create_label();
    let mut lower16 = rt.asm.create_label();
    let mut lower32 = rt.asm.create_label();
    let mut lower64 = rt.asm.create_label();
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

    // call ...
    stack::call(rt, rt.func_labels[&FnDef::ComputeAddress]);

    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // xor r14b, r14b
    rt.asm.xor(r14b, r14b).unwrap();

    // mov r8b, [r13] -> sub
    rt.asm.mov(r8b, ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();
    // or r14b, r8b
    rt.asm.or(r14b, r8b).unwrap();

    // mov r8b, [r13] -> store
    rt.asm.mov(r8b, ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();
    // shl r8b, 0x1
    rt.asm.shl(r8b, 0x1).unwrap();
    // or r14b, r8b
    rt.asm.or(r14b, r8b).unwrap();

    // mov r8b, [r13] -> dbits
    rt.asm.mov(r8b, ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();

    // movzx r9, [r13] -> dst
    rt.asm.movzx(r9, byte_ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();

    // cmp r8b, ...
    rt.asm
        .cmp(r8b, rt.mapper.index(VMBits::Lower64) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower64).unwrap();
    // cmp r8b, ...
    rt.asm
        .cmp(r8b, rt.mapper.index(VMBits::Lower32) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower32).unwrap();
    // cmp r8b, ...
    rt.asm
        .cmp(r8b, rt.mapper.index(VMBits::Lower16) as i32)
        .unwrap();
    // je ...
    rt.asm.je(lower16).unwrap();
    // cmp r8b, ...
    rt.asm
        .cmp(r8b, rt.mapper.index(VMBits::Higher8) as i32)
        .unwrap();
    // je ...
    rt.asm.je(higher8).unwrap();

    rt.asm.set_label(&mut lower8).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // lea rdx, [r12 + r9*8]
        rt.asm.lea(rdx, ptr(r12 + r9 * 8)).unwrap();
        // mov r8b, [rax]
        rt.asm.mov(r8b, ptr(rax)).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub8],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut higher8).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // lea rdx, [r12 + r9*8]
        rt.asm.lea(rdx, ptr(r12 + r9 * 8 + 0x1)).unwrap();
        // mov r8b, [rax]
        rt.asm.mov(r8b, ptr(rax)).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub8],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut lower16).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // lea rdx, [r12 + r9*8]
        rt.asm.lea(rdx, ptr(r12 + r9 * 8)).unwrap();
        // mov r8w, [rax]
        rt.asm.mov(r8w, ptr(rax)).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub16],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut lower32).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // lea rdx, [r12 + r9*8]
        rt.asm.lea(rdx, ptr(r12 + r9 * 8)).unwrap();
        // mov r8d, [rax]
        rt.asm.mov(r8d, ptr(rax)).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub32],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut lower64).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // lea rdx, [r12 + r9*8]
        rt.asm.lea(rdx, ptr(r12 + r9 * 8)).unwrap();
        // mov r8, [rax]
        rt.asm.mov(r8, ptr(rax)).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub64],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, r13
        rt.asm.mov(rax, r13).unwrap();

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
