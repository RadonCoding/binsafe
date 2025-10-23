use iced_x86::code_asm::{ptr, rax, rcx};

use crate::{
    runtime::{DataDef, FnDef, Runtime},
    vm::bytecode::VMOp,
};

pub fn build(rt: &mut Runtime) {
    // lea rax, [...]
    rt.asm
        .lea(rax, ptr(rt.data_labels[&DataDef::Handlers]))
        .unwrap();

    let table = [
        (VMOp::PushImm, FnDef::VmHandlerPushImm),
        (VMOp::PushReg64, FnDef::VmHandlerPushReg64),
        (VMOp::SetRegImm, FnDef::VmHandlerSetRegImm),
        (VMOp::SetRegReg, FnDef::VmHandlerSetRegReg),
        (VMOp::SetRegMem, FnDef::VmHandlerSetRegMem),
        (VMOp::SetMemReg, FnDef::VmHandlerSetMemReg),
        (VMOp::BranchRel, FnDef::VmHandlerBranchRel),
        (VMOp::BranchReg, FnDef::VmHandlerBranchReg),
        (VMOp::BranchMem, FnDef::VmHandlerBranchMem),
        (VMOp::Jcc, FnDef::VmHandlerJcc),
    ];

    for (op, func) in table {
        // lea rcx, [...]
        rt.asm.lea(rcx, ptr(rt.func_labels[&func])).unwrap();
        // mov [rax + ...], rcx
        rt.asm.mov(ptr(rax + op as u8 * 8), rcx).unwrap();
    }

    // ret
    rt.asm.ret().unwrap();
}
