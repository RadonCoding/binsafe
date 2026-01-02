use iced_x86::code_asm::{
    ax, byte_ptr, eax, ptr, r12, r12b, r13, r13b, r8, r9, r9b, rax, rcx, rdx,
};

use crate::{
    runtime::Runtime,
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

    // mov r12b, [rdx] -> dbits
    rt.asm.mov(r12b, ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // movzx r8, [rdx] -> dst
    rt.asm.movzx(r8, byte_ptr(rdx)).unwrap();
    // dec r8
    rt.asm.dec(r8).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // mov r13b, [rdx] -> sbits
    rt.asm.mov(r13b, ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // movzx r9, [rdx] -> src
    rt.asm.movzx(r9, byte_ptr(rdx)).unwrap();
    // dec r9
    rt.asm.dec(r9).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // cmp r12b, ...
    rt.asm.cmp(r12b, VMBits::Lower64 as u8 as i32).unwrap();
    // je ...
    rt.asm.je(lower64).unwrap();
    // cmp r12b, ...
    rt.asm.cmp(r12b, VMBits::Lower32 as u8 as i32).unwrap();
    // je ...
    rt.asm.je(lower32).unwrap();
    // cmp r12b, ...
    rt.asm.cmp(r12b, VMBits::Lower16 as u8 as i32).unwrap();
    // je ...
    rt.asm.je(lower16).unwrap();
    // cmp r12b, ...
    rt.asm.cmp(r12b, VMBits::Higher8 as u8 as i32).unwrap();
    // je ...
    rt.asm.je(higher8).unwrap();

    rt.asm.set_label(&mut lower8).unwrap();
    {
        let mut is_lower = rt.asm.create_label();

        // lea r9, [rcx + r9*8]
        rt.asm.lea(r9, ptr(rcx + r9 * 8)).unwrap();

        // cmp r13b, ...
        rt.asm.cmp(r13b, VMBits::Higher8 as u8 as i32).unwrap();
        // jne ...
        rt.asm.jne(is_lower).unwrap();

        // add r9, 0x1
        rt.asm.add(r9, 0x1).unwrap();

        rt.asm.set_label(&mut is_lower).unwrap();
        {
            // mov r9b, [r9]
            rt.asm.mov(r9b, ptr(r9)).unwrap();
            // mov [rcx + r8*8], r9b
            rt.asm.mov(ptr(rcx + r8 * 8), r9b).unwrap();
            // jmp ...
            rt.asm.jmp(epilogue).unwrap();
        }
    }

    rt.asm.set_label(&mut higher8).unwrap();
    {
        let mut is_lower = rt.asm.create_label();

        // lea r9, [rcx + r9*8]
        rt.asm.lea(r9, ptr(rcx + r9 * 8)).unwrap();

        // cmp r13b, ...
        rt.asm.cmp(r13b, VMBits::Higher8 as u8 as i32).unwrap();
        // jne ...
        rt.asm.jne(is_lower).unwrap();

        // add r9, 0x1
        rt.asm.add(r9, 0x1).unwrap();

        rt.asm.set_label(&mut is_lower).unwrap();
        {
            // mov r9b, [r9]
            rt.asm.mov(r9b, ptr(r9)).unwrap();
            // mov [rcx + r8*8], r9b
            rt.asm.mov(ptr(rcx + r8 * 8 + 0x1), r9b).unwrap();
            // jmp ...
            rt.asm.jmp(epilogue).unwrap();
        }
    }

    rt.asm.set_label(&mut lower16).unwrap();
    {
        // mov ax, [rcx + r9*8] -> src
        rt.asm.mov(ax, ptr(rcx + r9 * 8)).unwrap();
        // mov [rcx + r8*8], ax
        rt.asm.mov(ptr(rcx + r8 * 8), ax).unwrap();
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower32).unwrap();
    {
        // mov eax, [rcx + r9*8] -> src
        rt.asm.mov(eax, ptr(rcx + r9 * 8)).unwrap();
        // mov [rcx + r8*8], rax
        rt.asm.mov(ptr(rcx + r8 * 8), rax).unwrap();
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower64).unwrap();
    {
        // mov rax, [rcx + r9*8] -> src
        rt.asm.mov(rax, ptr(rcx + r9 * 8)).unwrap();
        // mov [rcx + r8*8], rax
        rt.asm.mov(ptr(rcx + r8 * 8), rax).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();

        // pop r13
        stack::pop(rt, r13);
        // pop r12
        stack::pop(rt, r12);
        // ret
        stack::ret(rt);
    }
}
