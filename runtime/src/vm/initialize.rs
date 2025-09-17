use iced_x86::code_asm::{ptr, rax, rcx};

use crate::{
    runtime::{DataDef, FnDef, Runtime},
    vm::bytecode::VMOp,
};

pub fn build(rt: &mut Runtime) {
    // lea rcx, [...]
    rt.asm
        .lea(rcx, ptr(rt.data_labels[&DataDef::HANDLERS]))
        .unwrap();

    let table = [
        (VMOp::SetRegImm, FnDef::VmHandlerSetRegImm),
        (VMOp::SetRegReg, FnDef::VmHandlerSetRegReg),
        (VMOp::SetRegMem, FnDef::VmHandlerSetRegMem),
        (VMOp::SetMemReg, FnDef::VmHandlerSetMemReg),
        (VMOp::CallRel, FnDef::VmHandlerCallRel),
        (VMOp::CallReg, FnDef::VmHandlerCallReg),
        (VMOp::CallMem, FnDef::VmHandlerCallMem),
    ];

    for (op, func) in table {
        // lea rax, [...]
        rt.asm.lea(rax, ptr(rt.func_labels[&func])).unwrap();
        // mov [rcx + op*8], rax
        rt.asm.mov(ptr(rcx + op as u8 * 8), rax).unwrap();
    }

    // ret
    rt.asm.ret().unwrap();
}
