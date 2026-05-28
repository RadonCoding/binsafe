use crate::vm::utils;
use iced_x86::code_asm::{eax, ptr, r8, rax, rcx, rdx};
use rand::seq::SliceRandom;

use crate::{
    runtime::{DataDef, FnDef, Runtime},
    vm::bytecode::{VMOp, VMReg},
};

pub mod add;
pub mod discard;
pub mod jcc;
pub mod load_addr;
pub mod load_imm;
pub mod load_mem;
pub mod load_reg;
pub mod nop;
pub mod store_mem;
pub mod store_reg;
pub mod sub;

pub fn initialize(rt: &mut Runtime) {
    let mut table = [
        (VMOp::Jcc, FnDef::VmHandlerJcc),
        (VMOp::LoadImmediate, FnDef::VmHandlerLoadImm),
        (VMOp::LoadRegister, FnDef::VmHandlerLoadReg),
        (VMOp::LoadMemory, FnDef::VmHandlerLoadMem),
        (VMOp::LoadAddress, FnDef::VmHandlerLoadAddr),
        (VMOp::StoreRegister, FnDef::VmHandlerStoreReg),
        (VMOp::StoreMemory, FnDef::VmHandlerStoreMem),
        (VMOp::Add, FnDef::VmHandlerAdd),
        (VMOp::Sub, FnDef::VmHandlerSub),
        (VMOp::Discard, FnDef::VmHandlerDiscard),
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
            utils::vreg::reg_add(rt, rax, VMReg::VImage, r8);

            // mov [rcx + ...], r8
            rt.asm.mov(ptr(rcx + rt.mapper.index(op) * 8), r8).unwrap();
        }
    });

    // ret
    rt.asm.ret().unwrap();
}
