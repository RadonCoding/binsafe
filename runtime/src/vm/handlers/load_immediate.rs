use iced_x86::code_asm::{eax, r12, r8, r8b, r8d, r8w, r9, rax, rcx};

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
    utils::vreg::load_reg(rt, r12, VMReg::VImmMul, r9);

    utils::width::dispatch(
        rt,
        rax,
        &mut epilogue,
        Some(Box::new(|rt| {
            // r8 -> source
            utils::bytecode::read_qword(rt, rcx, r8);
            // imul r8, [r12 + ...]
            utils::vreg::reg_imul(rt, r12, VMReg::VImmMul, r8);
            // sub r8, [r12 + ...]
            utils::vreg::reg_sub(rt, r12, VMReg::VImmAdd, r8);
        })),
        Some(Box::new(|rt| {
            // r8d -> source
            utils::bytecode::read_dword(rt, rcx, r8d);
            // imul r8d, [r12 + ...]
            utils::vreg::reg_imul(rt, r12, VMReg::VImmMul, r8d);
            // sub r8d, [r12 + ...]
            utils::vreg::reg_sub(rt, r12, VMReg::VImmAdd, r8d);
        })),
        None,
        Some(Box::new(|rt| {
            // r8w -> source
            utils::bytecode::read_word_zx(rt, rcx, r8d);
            // imul r8w, [r12 + ...]
            utils::vreg::reg_imul(rt, r12, VMReg::VImmMul, r8w);
            // sub r8w, [r12 + ...]
            utils::vreg::reg_sub(rt, r12, VMReg::VImmAdd, r8w);
        })),
        None,
        Some(Box::new(|rt| {
            // r8b -> source
            utils::bytecode::read_byte_zx(rt, rcx, r8d);
            // imul r8w, [r12 + ...]
            utils::vreg::reg_imul(rt, r12, VMReg::VImmMul, r8w);
            // sub r8b, [r12 + ...]
            utils::vreg::reg_sub(rt, r12, VMReg::VImmAdd, r8b);
            // movzx r8w, r8b
            rt.asm.movzx(r8w, r8b).unwrap();
        })),
        Some(Box::new(|rt| {
            // r8 -> source
            utils::bytecode::read_qword(rt, rcx, r8);
            // imul r8, [r12 + ...]
            utils::vreg::reg_imul(rt, r12, VMReg::VImmMul, r8);
            // sub r8, [r12 + ...]
            utils::vreg::reg_sub(rt, r12, VMReg::VImmAdd, r8);
        })),
        Some(Box::new(|rt| {
            // r8d -> source
            utils::bytecode::read_dword(rt, rcx, r8d);
            // imul r8d, [r12 + ...]
            utils::vreg::reg_imul(rt, r12, VMReg::VImmMul, r8d);
            // sub r8d, [r12 + ...]
            utils::vreg::reg_sub(rt, r12, VMReg::VImmAdd, r8d);
            // movsxd r8, r8d
            rt.asm.movsxd(r8, r8d).unwrap();
        })),
        Some(Box::new(|rt| {
            // r8w -> source
            utils::bytecode::read_word_zx(rt, rcx, r8d);
            // imul r8w, [r12 + ...]
            utils::vreg::reg_imul(rt, r12, VMReg::VImmMul, r8w);
            // sub r8w, [r12 + ...]
            utils::vreg::reg_sub(rt, r12, VMReg::VImmAdd, r8w);
            // movsx r8, r8w
            rt.asm.movsx(r8, r8w).unwrap();
        })),
        Some(Box::new(|rt| {
            // r8b -> source
            utils::bytecode::read_byte_zx(rt, rcx, r8d);
            // imul r8w, [r12 + ...]
            utils::vreg::reg_imul(rt, r12, VMReg::VImmMul, r8w);
            // sub r8b, [r12 + ...]
            utils::vreg::reg_sub(rt, r12, VMReg::VImmAdd, r8b);
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
