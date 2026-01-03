use iced_x86::code_asm::{byte_ptr, ptr, r8, r8b, r8d, rax, rcx, rdx, word_ptr};

use crate::{
    runtime::Runtime,
    vm::{bytecode::VMReg, stack, utils},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut byte = rt.asm.create_label();
    let mut word = rt.asm.create_label();
    let mut dword = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // sub [rcx + ...], 0x8
    utils::sub_vreg_imm_64(rt, rcx, 0x8, VMReg::Rsp);

    // mov r8b, [rdx] -> size
    rt.asm.mov(r8b, byte_ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

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
        // movsx r8, [rdx] -> src
        rt.asm.movsx(r8, byte_ptr(rdx)).unwrap();
        // add rdx, 0x1
        rt.asm.add(rdx, 0x1).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut word).unwrap();
    {
        // movsx r8, [rdx] -> src
        rt.asm.movsx(r8, word_ptr(rdx)).unwrap();
        // add rdx, 0x2
        rt.asm.add(rdx, 0x2).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut dword).unwrap();
    {
        // mov r8d, [rdx] -> src
        rt.asm.mov(r8d, ptr(rdx)).unwrap();
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
