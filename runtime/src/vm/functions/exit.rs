use iced_x86::code_asm::{ptr, r12, r12d, rsp};

use crate::{
    runtime::{DataDef, Runtime},
    vm::{bytecode::VMReg, utils, VREG_TO_REG},
};

pub fn build(rt: &mut Runtime) {
    let mut use_vex = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // mov r12d, [...]
    rt.asm
        .mov(r12d, ptr(rt.data_labels[&DataDef::VmStateTlsIndex]))
        .unwrap();
    // mov r12, gs:[0x1480 + r12*8]
    rt.asm.mov(r12, ptr(0x1480 + r12 * 8).gs()).unwrap();

    // mov rsp, [r12 + ...]
    utils::vreg::load_reg(rt, r12, VMReg::Rsp, rsp);

    // push [r12 + ...]
    utils::vreg::push(rt, r12, VMReg::Flags);
    // popfq
    rt.asm.popfq().unwrap();

    for (vreg, reg) in VREG_TO_REG {
        // mov ...,  [r12 + ...]
        utils::vreg::load_reg(rt, r12, *vreg, *reg);
    }

    // cmp [r12 + ...], 0x0
    utils::vreg::cmp_imm(rt, r12, VMReg::NBranch, 0x0);
    // je ...
    rt.asm.je(use_vex).unwrap();

    // push [r12 + ...]
    utils::vreg::push(rt, r12, VMReg::NBranch);
    // jmp ...
    rt.asm.jmp(epilogue).unwrap();

    rt.asm.set_label(&mut use_vex).unwrap();
    {
        // push [r12 + ...]
        utils::vreg::push(rt, r12, VMReg::NExit);
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov r12, [r12 + ...]
        utils::vreg::load_reg(rt, r12, VMReg::R12, r12);

        // ret
        rt.asm.ret().unwrap();
    }
}
