use iced_x86::code_asm::{
    ah, al, ax, byte_ptr, ptr, r12, r13, r13b, r8, r8b, r8d, r8w, r9w, rax, rcx, rdx,
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

    // mov r12, rdx
    rt.asm.mov(r12, rdx).unwrap();

    // mov r13b, [r12] -> bits
    rt.asm.mov(r13b, ptr(r12)).unwrap();
    // add r12, 0x1
    rt.asm.add(r12, 0x1).unwrap();

    // movzx r8, [r12] -> dst
    rt.asm.movzx(r8, byte_ptr(r12)).unwrap();
    // dec r8
    rt.asm.dec(r8).unwrap();
    // add r12, 0x1
    rt.asm.add(r12, 0x1).unwrap();

    // mov al, [r12] -> sub
    rt.asm.mov(al, ptr(r12)).unwrap();
    // add r12, 0x1
    rt.asm.add(r12, 0x1).unwrap();

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
        // lea rdx, [rcx + r8*8]
        rt.asm.lea(rdx, ptr(rcx + r8 * 8)).unwrap();
        // mov r8b, [r12]
        rt.asm.mov(r8b, ptr(r12)).unwrap();
        // add r12, 0x1
        rt.asm.add(r12, 0x1).unwrap();
        // xor ah, ah
        rt.asm.xor(ah, ah).unwrap();
        // mov r9w, ax
        rt.asm.mov(r9w, ax).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub8],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut higher8).unwrap();
    {
        // lea rdx, [rcx + r8*8 + 1]
        rt.asm.lea(rdx, ptr(rcx + r8 * 8 + 1)).unwrap();
        // mov r8b, [r12]
        rt.asm.mov(r8b, ptr(r12)).unwrap();
        // add r12, 0x1
        rt.asm.add(r12, 0x1).unwrap();
        // xor ah, ah
        rt.asm.xor(ah, ah).unwrap();
        // mov r9w, ax
        rt.asm.mov(r9w, ax).unwrap();
        // call ...
        stack::call_with_label(
            rt,
            rt.func_labels[&FnDef::VmArithmeticAddSub8],
            &mut epilogue,
        );
    }

    rt.asm.set_label(&mut lower16).unwrap();
    {
        // lea rdx, [rcx + r8*8]
        rt.asm.lea(rdx, ptr(rcx + r8 * 8)).unwrap();
        // mov r8w, [r12]
        rt.asm.mov(r8w, ptr(r12)).unwrap();
        // add r12, 0x2
        rt.asm.add(r12, 0x2).unwrap();
        // xor ah, ah
        rt.asm.xor(ah, ah).unwrap();
        // mov r9w, ax
        rt.asm.mov(r9w, ax).unwrap();
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
        // mov r8d, [r12]
        rt.asm.mov(r8d, ptr(r12)).unwrap();
        // add r12, 0x4
        rt.asm.add(r12, 0x4).unwrap();
        // mov ah, 0x1
        rt.asm.mov(ah, 0x1).unwrap();
        // mov r9w, ax
        rt.asm.mov(r9w, ax).unwrap();
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
        // mov r8, [r12]
        rt.asm.mov(r8, ptr(r12)).unwrap();
        // add r12, 0x8
        rt.asm.add(r12, 0x8).unwrap();
        // xor ah, ah
        rt.asm.xor(ah, ah).unwrap();
        // mov r9w, ax
        rt.asm.mov(r9w, ax).unwrap();
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

        // pop r13
        stack::pop(rt, r13);
        // pop r12
        stack::pop(rt, r12);
        // ret
        stack::ret(rt);
    }
}
