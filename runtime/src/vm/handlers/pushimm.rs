use iced_x86::code_asm::{byte_ptr, dword_ptr, r8, r8b, rax, rcx, rdx, word_ptr};

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{VMBits, VMReg},
        stack, utils,
    },
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut lower8 = rt.asm.create_label();
    let mut lower16 = rt.asm.create_label();
    let mut lower32 = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // sub [rcx + ...], 0x8
    utils::sub_vreg_imm_64(rt, rcx, 0x8, VMReg::Rsp);

    // mov r8b, [rdx] -> bits
    rt.asm.mov(r8b, byte_ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // cmp r8b, ...
    rt.asm.cmp(r8b, VMBits::Lower32 as u8 as i32).unwrap();
    // je ...
    rt.asm.je(lower32).unwrap();
    // cmp r8b, ...
    rt.asm.cmp(r8b, VMBits::Lower16 as u8 as i32).unwrap();
    // je ...
    rt.asm.je(lower16).unwrap();

    rt.asm.set_label(&mut lower8).unwrap();
    {
        // movsx r8, [rdx] -> src
        rt.asm.movsx(r8, byte_ptr(rdx)).unwrap();
        // add rdx, 0x1
        rt.asm.add(rdx, 0x1).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower16).unwrap();
    {
        // movsx r8, [rdx] -> src
        rt.asm.movsx(r8, word_ptr(rdx)).unwrap();
        // add rdx, 0x2
        rt.asm.add(rdx, 0x2).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower32).unwrap();
    {
        // movsxd r8, [rdx] -> src
        rt.asm.movsxd(r8, dword_ptr(rdx)).unwrap();
        // add rdx, 0x4
        rt.asm.add(rdx, 0x4).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, [rcx + ...]; mov [rax], r8
        utils::store_vreg_mem_64(rt, rcx, rax, r8, VMReg::Rsp);

        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();
        // ret
        stack::ret(rt);
    }
}
