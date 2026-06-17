use iced_x86::code_asm::{eax, r12, r8, r8b, r8d, r8w, r9, r9b, r9d, r9w, rax, rcx};

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMReg,
        utils::{self, scratch},
    },
};

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // eax -> width
    utils::bytecode::read_byte_zx(rt, rcx, eax);

    // mov r9, [r12 + ...]
    utils::vreg::load_reg(rt, r12, VMReg::VImm, r9);

    utils::width::dispatch(
        rt,
        rax,
        &mut epilogue,
        Some(Box::new(|rt| {
            // r8  -> source
            utils::bytecode::read_qword(rt, rcx, r8);
            // xor r8, r9
            rt.asm.xor(r8, r9).unwrap();
        })),
        Some(Box::new(|rt| {
            // r8d  -> source
            utils::bytecode::read_dword(rt, rcx, r8d);
            // xor r8d, r9d
            rt.asm.xor(r8d, r9d).unwrap();
        })),
        None,
        Some(Box::new(|rt| {
            // r8d  -> source
            utils::bytecode::read_word_zx(rt, rcx, r8d);
            // xor r8w, r9w
            rt.asm.xor(r8w, r9w).unwrap();
        })),
        Some(Box::new(|rt| {
            // r8d  -> source
            utils::bytecode::read_byte_zx(rt, rcx, r8d);
            // shr r9, 0x8
            rt.asm.shr(r9, 0x8u32).unwrap();
            // xor r8b, r9b
            rt.asm.xor(r8b, r9b).unwrap();
        })),
        Some(Box::new(|rt| {
            // r8d  -> source
            utils::bytecode::read_byte_zx(rt, rcx, r8d);
            // xor r8b, r9b
            rt.asm.xor(r8b, r9b).unwrap();
        })),
        Some(Box::new(|rt| {
            // r8  -> source
            utils::bytecode::read_qword(rt, rcx, r8);
            // xor r8, r9
            rt.asm.xor(r8, r9).unwrap();
        })),
        Some(Box::new(|rt| {
            // r8d  -> source
            utils::bytecode::read_dword(rt, rcx, r8d);
            // xor r8d, r9d
            rt.asm.xor(r8d, r9d).unwrap();
            // movsxd r8, r8d
            rt.asm.movsxd(r8, r8d).unwrap();
        })),
        Some(Box::new(|rt| {
            // r8d  -> source
            utils::bytecode::read_word_zx(rt, rcx, r8d);
            // xor r8w, r9w
            rt.asm.xor(r8w, r9w).unwrap();
            // movsx r8, r8w
            rt.asm.movsx(r8, r8w).unwrap();
        })),
        Some(Box::new(|rt| {
            // r8d  -> source
            utils::bytecode::read_byte_zx(rt, rcx, r8d);
            // xor r8b, r9b
            rt.asm.xor(r8b, r9b).unwrap();
            // movsx r8, r8b
            rt.asm.movsx(r8, r8b).unwrap();
        })),
        None,
        None,
    );

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // store r8
        scratch::store(rt, r12, r8);

        // mov rax, rcx
        rt.asm.mov(rax, rcx).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
