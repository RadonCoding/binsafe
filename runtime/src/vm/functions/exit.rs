use iced_x86::code_asm::{r12, rsp};

use crate::{
    runtime::{FnDef, Runtime},
    vm::{bytecode::VMReg, utils},
};

pub fn build(rt: &mut Runtime) {
    let mut no_branch = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // mov rsp, [r12 + ...]
    utils::vreg::load_reg(rt, r12, VMReg::Rsp, rsp);

    // call ...
    rt.asm
        .call(rt.function_labels[&FnDef::VmVectorsRestore])
        .unwrap();
    // call ...
    rt.asm
        .call(rt.function_labels[&FnDef::VmRegistersRestore])
        .unwrap();

    // cmp [r12 + ...], 0x0
    utils::vreg::cmp_imm(rt, r12, VMReg::NBranch, 0x0);
    // je ...
    rt.asm.je(no_branch).unwrap();

    // push [r12 + ...]
    utils::vreg::push(rt, r12, VMReg::NBranch);
    // jmp ...
    rt.asm.jmp(epilogue).unwrap();

    rt.asm.set_label(&mut no_branch).unwrap();
    {
        // push [r12 + ...]
        utils::vreg::push(rt, r12, VMReg::NExit);
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // push [r12 + ...]
        utils::vreg::push(rt, r12, VMReg::Flags);
        // popfq
        rt.asm.popfq().unwrap();

        // mov r12, [r12 + ...]
        utils::vreg::load_reg(rt, r12, VMReg::R12, r12);

        // ret
        rt.asm.ret().unwrap();
    }
}
