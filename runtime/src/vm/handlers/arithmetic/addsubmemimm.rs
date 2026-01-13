use iced_x86::code_asm::{ptr, r12, r13, r14, r14b, r8, r8b, r8d, r8w, r9b, rax, rcx, rdx};

use crate::{
    runtime::{FnDef, Runtime},

    vm::stack,
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut byte = rt.asm.create_label();
    let mut word = rt.asm.create_label();
    let mut dword = rt.asm.create_label();
    let mut qword = rt.asm.create_label();
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

    // or r14b, 0x4 -> memory
    rt.asm.or(r14b, 0x4).unwrap();

    // mov r8b, [r13] -> size
    rt.asm.mov(r8b, ptr(r13)).unwrap();
    // add r13, 0x1
    rt.asm.add(r13, 0x1).unwrap();

    // cmp r8b, ...
    rt.asm.cmp(r8b, 0x8).unwrap();
    // je ...
    rt.asm.je(qword).unwrap();
    // cmp r8b, ...
    rt.asm.cmp(r8b, 0x4).unwrap();
    // je ...
    rt.asm.je(dword).unwrap();
    // cmp r8b, ...
    rt.asm.cmp(r8b, 0x2).unwrap();
    // je ...
    rt.asm.je(word).unwrap();

    rt.asm.set_label(&mut byte).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // mov rdx, rax
        rt.asm.mov(rdx, rax).unwrap();
        // mov r8b, [r13]
        rt.asm.mov(r8b, ptr(r13)).unwrap();
        // add r13, 0x1
        rt.asm.add(r13, 0x1).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub8],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut word).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // mov rdx, rax
        rt.asm.mov(rdx, rax).unwrap();
        // mov r8b, [r13]
        rt.asm.mov(r8w, ptr(r13)).unwrap();
        // add r13, 0x1
        rt.asm.add(r13, 0x2).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub16],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut dword).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // mov rdx, rax
        rt.asm.mov(rdx, rax).unwrap();
        // mov r8d, [r13]
        rt.asm.mov(r8d, ptr(r13)).unwrap();
        // add r13, 0x1
        rt.asm.add(r13, 0x4).unwrap();
        // mov r9b, r14b
        rt.asm.mov(r9b, r14b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub32],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut qword).unwrap();
    {
        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // mov rdx, rax
        rt.asm.mov(rdx, rax).unwrap();
        // mov r8, [r13]
        rt.asm.mov(r8, ptr(r13)).unwrap();
        // add r13, 0x8
        rt.asm.add(r13, 0x8).unwrap();
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
