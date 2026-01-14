use iced_x86::code_asm::{eax, ptr, r8, rax, rcx, rdx};
use rand::seq::SliceRandom;

use crate::{
    runtime::{DataDef, FnDef, Runtime},
    vm::{
        bytecode::{VMOp, VMReg},
        utils,
    },
};

pub mod arithmetic;
pub mod branchimm;
pub mod branchmem;
pub mod branchreg;
pub mod jcc;
pub mod nop;
pub mod popreg;
pub mod pushimm;
pub mod pushpopregs;
pub mod pushreg;
pub mod setmemimm;
pub mod setmemreg;
pub mod setregimm;
pub mod setregmem;
pub mod setregreg;

pub fn initialize(rt: &mut Runtime) {
    let mut table = [
        (VMOp::PushPopRegs, FnDef::VmHandlerPushPopRegs),
        (VMOp::PushImm, FnDef::VmHandlerPushImm),
        (VMOp::PushReg, FnDef::VmHandlerPushReg),
        (VMOp::PopReg, FnDef::VmHandlerPopReg),
        (VMOp::SetRegImm, FnDef::VmHandlerSetRegImm),
        (VMOp::SetRegReg, FnDef::VmHandlerSetRegReg),
        (VMOp::SetRegMem, FnDef::VmHandlerSetRegMem),
        (VMOp::SetMemImm, FnDef::VmHandlerSetMemImm),
        (VMOp::SetMemReg, FnDef::VmHandlerSetMemReg),
        (VMOp::AddSubRegImm, FnDef::VmHandlerAddSubRegImm),
        (VMOp::AddSubRegReg, FnDef::VmHandlerAddSubRegReg),
        (VMOp::AddSubRegMem, FnDef::VmHandlerAddSubRegMem),
        (VMOp::AddSubMemImm, FnDef::VmHandlerAddSubMemImm),
        (VMOp::AddSubMemReg, FnDef::VmHandlerAddSubMemReg),
        (VMOp::BranchImm, FnDef::VmHandlerBranchImm),
        (VMOp::BranchReg, FnDef::VmHandlerBranchReg),
        (VMOp::BranchMem, FnDef::VmHandlerBranchMem),
        (VMOp::Jcc, FnDef::VmHandlerJcc),
        (VMOp::Nop, FnDef::VmHandlerNop),
    ];

    let mut rng = rand::thread_rng();
    table.shuffle(&mut rng);

    // mov eax, [...]
    rt.asm
        .mov(eax, ptr(rt.data_labels[&DataDef::VmStateTlsIndex]))
        .unwrap();
    // mov rax, [0x1480 + rcx*8]
    rt.asm.mov(rax, ptr(0x1480 + rax * 8).gs()).unwrap();

    // lea rcx, [...]
    rt.asm
        .lea(rcx, ptr(rt.data_labels[&DataDef::VmHandlers]))
        .unwrap();

    rt.with_chain(|rt| {
        // xor rdx, rdx
        rt.asm.xor(rdx, rdx).unwrap();

        for (op, def) in table {
            let key = rt.mark_as_encrypted(rt.func_labels[&def]);
            // mov r8, ...
            rt.asm.mov(r8, 0x0u64).unwrap();
            // xor rdx, r8
            rt.asm.xor(rdx, r8).unwrap();
            // mov r8, ...
            rt.asm.mov(r8, key).unwrap();
            // xor rdx, r8
            rt.asm.xor(rdx, r8).unwrap();

            // mov r8, rdx
            rt.asm.mov(r8, rdx).unwrap();

            // add r8, [...]
            utils::add_reg_vreg_64(rt, rax, VMReg::VB, r8);

            // mov [rcx + ...], r8
            rt.asm.mov(ptr(rcx + rt.mapper.index(op) * 8), r8).unwrap();
        }
    });

    // ret
    rt.asm.ret().unwrap();
}
