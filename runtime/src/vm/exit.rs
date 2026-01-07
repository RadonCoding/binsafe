use iced_x86::code_asm::{byte_ptr, ptr, r12, rsp};

use crate::{
    runtime::{BoolDef, DataDef, Runtime},
    vm::{bytecode::VMReg, utils, VREG_TO_REG},
};

pub fn build(rt: &mut Runtime) {
    // lea r12, [...]
    rt.asm
        .lea(r12, ptr(rt.data_labels[&DataDef::VmState]))
        .unwrap();

    // mov rsp, [r12 + ...]
    utils::mov_reg_vreg_64(rt, r12, VMReg::Rsp, rsp);

    // mov rcx, [...]
    utils::push_vreg_64(rt, r12, VMReg::Flags);
    // popfq
    rt.asm.popfq().unwrap();

    for (vreg, reg) in VREG_TO_REG {
        // mov ...,  [r12 + ...]
        utils::mov_reg_vreg_64(rt, r12, *vreg, *reg);
    }

    // push [r12 + ...]
    utils::push_vreg_64(rt, r12, VMReg::Vip);

    // mov r12, [r12 + ...]
    utils::mov_reg_vreg_64(rt, r12, VMReg::R12, r12);

    // mov [...], 0x0
    rt.asm
        .mov(byte_ptr(rt.bool_labels[&BoolDef::VmIsLocked]), 0x0)
        .unwrap();

    // ret
    rt.asm.ret().unwrap();
}
