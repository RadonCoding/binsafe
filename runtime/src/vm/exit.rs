use iced_x86::code_asm::{ptr, r12, r12d, rsp};

use crate::{
    runtime::{DataDef, Runtime},
    vm::{bytecode::VMReg, utils, VREG_TO_REG},
};

pub fn build(rt: &mut Runtime) {
    // mov r12d, [...]
    rt.asm
        .mov(r12d, ptr(rt.data_labels[&DataDef::VmStateTlsIndex]))
        .unwrap();
    // mov r12, gs:[0x1480 + r12*8]
    rt.asm.mov(r12, ptr(0x1480 + r12 * 8).gs()).unwrap();

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
    utils::push_vreg_64(rt, r12, VMReg::Vra);

    // mov r12, [r12 + ...]
    utils::mov_reg_vreg_64(rt, r12, VMReg::R12, r12);

    // ret
    rt.asm.ret().unwrap();
}
