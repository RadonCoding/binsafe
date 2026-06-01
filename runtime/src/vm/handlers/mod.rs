use crate::vm::utils;
use iced_x86::code_asm::{eax, ptr, r8, rax, rcx, rdx};
use rand::seq::SliceRandom;

use crate::{
    runtime::{DataDef, FnDef, Runtime},
    vm::bytecode::{VMOp, VMReg},
};

/// Emits a build function for an arithmetic handler whose only variation is the assembled mnemonic, loading the two scratch operands into r13 and r8, dispatching on width, then handing off to [`crate::runtime::FnDef::VmFlags`] before storing the result and restoring callee-saved registers.
macro_rules! arithmetic {
    ($op:ident) => {
        use iced_x86::code_asm::{al, r12, r13, r13b, r13d, r13w, r8, r8b, r8d, r8w, rax, rdx};

        use crate::{
            runtime::{FnDef, Runtime},
            vm::utils::{self, scratch, stack},
        };

        // unsigned char* (unsigned long*, unsigned char*)
        pub fn build(rt: &mut Runtime) {
            let mut epilogue = rt.asm.create_label();

            // push r12
            stack::push(rt, r12);
            // push r13
            stack::push(rt, r13);
            // mov r12, rdx
            rt.asm.mov(r12, rdx).unwrap();

            // al -> width
            utils::bytecode::read_byte(rt, r12, al);

            // load r8
            scratch::load(rt, r8);
            // load r13
            scratch::load(rt, r13);

            utils::width::dispatch(
                rt,
                al,
                &mut epilogue,
                |rt| {
                    rt.asm.$op(r13, r8).unwrap();
                },
                |rt| {
                    rt.asm.$op(r13d, r8d).unwrap();
                },
                |rt| {
                    rt.asm.$op(r13w, r8w).unwrap();
                },
                |rt| {
                    rt.asm.$op(r13b, r8b).unwrap();
                },
                |rt| {
                    rt.asm.$op(r13b, r8b).unwrap();
                },
                |rt| {
                    rt.asm.$op(r13d, r8d).unwrap();
                },
                |rt| {
                    rt.asm.$op(r13w, r8w).unwrap();
                },
                |rt| {
                    rt.asm.$op(r13b, r8b).unwrap();
                },
            );

            rt.asm.set_label(&mut epilogue).unwrap();
            {
                // pushfq
                stack::pushfq(rt);
                // call ...
                stack::call(rt, rt.func_labels[&FnDef::VmFlags]);

                // store r13
                scratch::store(rt, r13);

                // mov rax, r12
                rt.asm.mov(rax, r12).unwrap();
                // pop r13
                stack::pop(rt, r13);
                // pop r12
                stack::pop(rt, r12);
                // ret
                stack::ret(rt);
            }
        }
    };
}

pub(crate) use arithmetic;

pub mod add;
pub mod and;
pub mod discard;
pub mod flags;
pub mod jcc;
pub mod load_address;
pub mod load_immediate;
pub mod load_memory;
pub mod load_register;
pub mod or;
pub mod pop;
pub mod push;
pub mod ret;
pub mod store_memory;
pub mod store_register;
pub mod sub;
pub mod test;
pub mod xor;

pub fn initialize(rt: &mut Runtime) {
    let mut table = [
        (VMOp::Jcc, FnDef::VmHandlerJcc),
        (VMOp::Ret, FnDef::VmHandlerRet),
        (VMOp::LoadImmediate, FnDef::VmHandlerLoadImmediate),
        (VMOp::LoadRegister, FnDef::VmHandlerLoadRegister),
        (VMOp::LoadMemory, FnDef::VmHandlerLoadMemory),
        (VMOp::LoadAddress, FnDef::VmHandlerLoadAddress),
        (VMOp::StoreRegister, FnDef::VmHandlerStoreRegister),
        (VMOp::StoreMemory, FnDef::VmHandlerStoreMemory),
        (VMOp::Add, FnDef::VmHandlerAdd),
        (VMOp::Sub, FnDef::VmHandlerSub),
        (VMOp::And, FnDef::VmHandlerAnd),
        (VMOp::Or, FnDef::VmHandlerOr),
        (VMOp::Xor, FnDef::VmHandlerXor),
        (VMOp::Test, FnDef::VmHandlerTest),
        (VMOp::Push, FnDef::VmHandlerPush),
        (VMOp::Pop, FnDef::VmHandlerPop),
        (VMOp::Discard, FnDef::VmHandlerDiscard),
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
            rt.asm
                .mov(ptr(rcx + rt.mapper.index(op) as i32 * 8), r8)
                .unwrap();
        }
    });

    // ret
    rt.asm.ret().unwrap();
}
