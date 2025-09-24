use iced_x86::code_asm::{eax, ptr, r12, r13, r14, rax, rbp, rcx, rdx, rsp};

use crate::{
    define_offset,
    runtime::{FnDef, Runtime},
    vm::{
        bytecode::{VMReg, VM_REG_COUNT},
        utils,
    },
};

const CONTEXT_STATE_MAP: &[(i32, VMReg)] = &[
    (0x78, VMReg::Rax),
    (0x80, VMReg::Rcx),
    (0x88, VMReg::Rdx),
    (0x90, VMReg::Rbx),
    (0x98, VMReg::Rsp),
    (0xA0, VMReg::Rbp),
    (0xA8, VMReg::Rsi),
    (0xB0, VMReg::Rdi),
    (0xB8, VMReg::R8),
    (0xC0, VMReg::R9),
    (0xC8, VMReg::R10),
    (0xD0, VMReg::R11),
    (0xD8, VMReg::R12),
    (0xE0, VMReg::R13),
    (0xE8, VMReg::R14),
    (0xF0, VMReg::R15),
    (0xF8, VMReg::Rip),
    (0x44, VMReg::Flags),
];

// bool (CONTEXT*)
pub fn build(rt: &mut Runtime) {
    let mut lookup = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    let mut offset = 0;

    define_offset!(state, offset, (VM_REG_COUNT * 8) as i32);

    let stack_size = (offset + 0xF) & !0xF;

    // push rbp
    rt.asm.push(rbp).unwrap();
    // mov rbp, rsp
    rt.asm.mov(rbp, rsp).unwrap();
    // sub rsp, ...
    rt.asm.sub(rsp, stack_size).unwrap();

    // push r12
    rt.asm.push(r12).unwrap();
    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();

    // lea r12, [rbp - ...]
    rt.asm.lea(r12, ptr(rbp - state)).unwrap();
    // mov r13, rcx
    rt.asm.mov(r13, rcx).unwrap();

    for &(offset, reg) in CONTEXT_STATE_MAP {
        if reg == VMReg::Flags {
            // mov eax, [r13 + ...]
            rt.asm.mov(eax, ptr(r13 + offset)).unwrap();
        } else {
            // mov rax, [r13 + ...]
            rt.asm.mov(rax, ptr(r13 + offset)).unwrap();
        }
        // mov [r12 + ...], rax
        utils::mov_vreg_reg_64(rt, r12, rax, reg);
    }

    // xor r14, r14
    rt.asm.xor(r14, r14).unwrap();

    rt.asm.set_label(&mut lookup).unwrap();
    {
        // mov rcx, [r12 + ...]
        utils::mov_reg_vreg_64(rt, r12, VMReg::Rip, rcx);
        // call ...
        rt.asm.call(rt.func_labels[&FnDef::VmSearch]).unwrap();

        // test rax, rax
        rt.asm.test(rax, rax).unwrap();
        // jz ...
        rt.asm.jz(epilogue).unwrap();

        // mov r14, 0x1
        rt.asm.mov(r14, 0x1u64).unwrap();

        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // mov rdx, rax
        rt.asm.mov(rdx, rax).unwrap();
        // call ...
        rt.asm.call(rt.func_labels[&FnDef::VmDispatcher]).unwrap();

        // jmp ...
        rt.asm.jmp(lookup).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        for &(offset, reg) in CONTEXT_STATE_MAP {
            // mov rax, [r12 + ...]
            utils::mov_reg_vreg_64(rt, r12, reg, rax);

            if reg == VMReg::Flags {
                // mov [r13 + ...], rax
                rt.asm.mov(ptr(r13 + offset), eax).unwrap();
            } else {
                // mov [r13 + ...], rax
                rt.asm.mov(ptr(r13 + offset), rax).unwrap();
            }
        }

        // mov rax, r14
        rt.asm.mov(rax, r14).unwrap();

        // pop r14
        rt.asm.pop(r14).unwrap();
        // pop r13
        rt.asm.pop(r13).unwrap();
        // pop r12
        rt.asm.pop(r12).unwrap();

        // mov rsp, rbp
        rt.asm.mov(rsp, rbp).unwrap();
        // pop rbp
        rt.asm.pop(rbp).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
