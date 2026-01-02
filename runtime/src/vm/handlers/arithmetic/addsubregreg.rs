use iced_x86::code_asm::{
    al, byte_ptr, ptr, r12, r13, r13b, r14, r14b, r15, r15b, r8, r8b, r8d, r8w, r9, r9b, rax, rcx,
    rdx,
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
    // push r15
    stack::push(rt, r15);

    // mov r12, rdx
    rt.asm.mov(r12, rdx).unwrap();

    // mov r13b, [r12] -> dbits
    rt.asm.mov(r13b, ptr(r12)).unwrap();
    // add r12, 0x1
    rt.asm.add(r12, 0x1).unwrap();

    // movzx r8, [r12] -> dst
    rt.asm.movzx(r8, byte_ptr(r12)).unwrap();
    // dec r8
    rt.asm.dec(r8).unwrap();
    // add r12, 0x1
    rt.asm.add(r12, 0x1).unwrap();

    // mov r14b, [r12] -> sbits
    rt.asm.mov(r14b, ptr(r12)).unwrap();
    // add r12, 0x1
    rt.asm.add(r12, 0x1).unwrap();

    // movzx r9, [r12] -> src
    rt.asm.movzx(r9, byte_ptr(r12)).unwrap();
    // dec r9
    rt.asm.dec(r9).unwrap();
    // add r12, 0x1
    rt.asm.add(r12, 0x1).unwrap();

    // xor r15b, r15b
    rt.asm.xor(r15b, r15b).unwrap();

    // mov al, [r12] -> sub
    rt.asm.mov(al, ptr(r12)).unwrap();
    // add r12, 0x1
    rt.asm.add(r12, 0x1).unwrap();
    // or r15b, al
    rt.asm.or(r15b, al).unwrap();

    // mov al, [r12] -> store
    rt.asm.mov(al, ptr(r12)).unwrap();
    // add r12, 0x1
    rt.asm.add(r12, 0x1).unwrap();
    // shl al, 0x1
    rt.asm.shl(al, 0x1).unwrap();
    // or r15b, al
    rt.asm.or(r15b, al).unwrap();

    // cmp r13b, ...
    rt.asm.cmp(r13b, VMBits::Lower64 as u8 as i32).unwrap();
    // je ...
    rt.asm.je(lower64).unwrap();
    // cmp r13b, ...
    rt.asm.cmp(r13b, VMBits::Lower32 as u8 as i32).unwrap();
    // je ...
    rt.asm.je(lower32).unwrap();
    // cmp r13b, ...
    rt.asm.cmp(r13b, VMBits::Lower16 as u8 as i32).unwrap();
    // je ...
    rt.asm.je(lower16).unwrap();
    // cmp r13b, ...
    rt.asm.cmp(r13b, VMBits::Higher8 as u8 as i32).unwrap();
    // je ...
    rt.asm.je(higher8).unwrap();

    rt.asm.set_label(&mut lower8).unwrap();
    {
        let mut is_lower = rt.asm.create_label();

        // lea rdx, [rcx + r8*8]
        rt.asm.lea(rdx, ptr(rcx + r8 * 8)).unwrap();

        // lea r8, [rcx + r9*8]
        rt.asm.lea(r8, ptr(rcx + r9 * 8)).unwrap();

        // cmp r14b, ...
        rt.asm.cmp(r14b, VMBits::Higher8 as u8 as i32).unwrap();
        // jne ...
        rt.asm.jne(is_lower).unwrap();

        // add r8, 0x1
        rt.asm.add(r8, 0x1).unwrap();

        rt.asm.set_label(&mut is_lower).unwrap();
        {
            // mov r8b, [r8]
            rt.asm.mov(r8b, ptr(r8)).unwrap();
            // mov r9b, r15b
            rt.asm.mov(r9b, r15b).unwrap();
            // call ...
            stack::call_with_label(
                rt,
                rt.func_labels[&FnDef::VmArithmeticAddSub8],
                &mut epilogue,
            );
        }
    }

    rt.asm.set_label(&mut higher8).unwrap();
    {
        let mut is_lower = rt.asm.create_label();

        // lea rdx, [rcx + r8*8 + 0x1]
        rt.asm.lea(rdx, ptr(rcx + r8 * 8 + 0x1)).unwrap();

        // lea r8, [rcx + r9*8]
        rt.asm.lea(r8, ptr(rcx + r9 * 8)).unwrap();

        // cmp r14b, ...
        rt.asm.cmp(r14b, VMBits::Higher8 as u8 as i32).unwrap();
        // jne ...
        rt.asm.jne(is_lower).unwrap();

        // add r8, 0x1
        rt.asm.add(r8, 0x1).unwrap();

        rt.asm.set_label(&mut is_lower).unwrap();
        {
            // mov r8b, [r8]
            rt.asm.mov(r8b, ptr(r8)).unwrap();
            // mov r9b, r15b
            rt.asm.mov(r9b, r15b).unwrap();
            // call ...
            stack::call_with_label(
                rt,
                rt.func_labels[&FnDef::VmArithmeticAddSub8],
                &mut epilogue,
            );
        }
    }

    rt.asm.set_label(&mut lower16).unwrap();
    {
        // lea rdx, [rcx + r8*8]
        rt.asm.lea(rdx, ptr(rcx + r8 * 8)).unwrap();
        // mov r8w, [rcx + r9*8]
        rt.asm.mov(r8w, ptr(rcx + r9 * 8)).unwrap();
        // mov r9b, r15b
        rt.asm.mov(r9b, r15b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub16],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut lower32).unwrap();
    {
        // lea rdx, [rcx + r8*8]
        rt.asm.lea(rdx, ptr(rcx + r8 * 8)).unwrap();
        // mov r8d, [rcx + r9*8]
        rt.asm.mov(r8d, ptr(rcx + r9 * 8)).unwrap();
        // mov r9b, r15b
        rt.asm.mov(r9b, r15b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub32],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut lower64).unwrap();
    {
        // lea rdx, [rcx + r8*8]
        rt.asm.lea(rdx, ptr(rcx + r8 * 8)).unwrap();
        // mov r8, [rcx + r9*8]
        rt.asm.mov(r8, ptr(rcx + r9 * 8)).unwrap();
        // mov r9b, r15b
        rt.asm.mov(r9b, r15b).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub64],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, r12
        rt.asm.mov(rax, r12).unwrap();

        // pop r14
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
