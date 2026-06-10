use iced_x86::code_asm::{ptr, r8, rax, rcx, rdx};
use rand::seq::SliceRandom;

use crate::{
    runtime::{DataDef, FnDef, Runtime},
    vm::bytecode::VMOp,
};

#[macro_export]
macro_rules! __arithmetic {
    ($rt:expr, $operation:ident, r8, $epilogue:expr) => {
        $crate::vm::utils::width::dispatch_register(
            $rt,
            al,
            $epilogue,
            |rt| {
                rt.asm.$operation(r14, r8).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14d, r8d).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14w, r8w).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14b, r8b).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14b, r8b).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14, r8).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14d, r8d).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14w, r8w).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14b, r8b).unwrap();
            },
        );
    };
    ($rt:expr, $operation:ident, shift, $epilogue:expr) => {
        $rt.asm.mov(cl, r8b).unwrap();
        $crate::vm::utils::width::dispatch_register(
            $rt,
            al,
            $epilogue,
            |rt| {
                rt.asm.$operation(r14, cl).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14d, cl).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14w, cl).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14b, cl).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14b, cl).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14, cl).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14d, cl).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14w, cl).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14b, cl).unwrap();
            },
        );
    };
    ($rt:expr, $operation:ident, bitscan, $epilogue:expr) => {
        $crate::vm::utils::width::dispatch_register(
            $rt,
            al,
            $epilogue,
            |rt| {
                rt.asm.$operation(r14, r8).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14d, r8d).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14w, r8w).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14w, r8w).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14w, r8w).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14, r8).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14d, r8d).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14w, r8w).unwrap();
            },
            |rt| {
                rt.asm.$operation(r14w, r8w).unwrap();
            },
        );
    };
    ($rt:expr, $operation:ident, carry, $epilogue:expr) => {
        // r9d -> flags
        $crate::vm::utils::vreg::load_reg32($rt, r12, $crate::vm::bytecode::VMReg::Flags, r9d);
        $crate::vm::utils::width::dispatch_register(
            $rt,
            al,
            $epilogue,
            |rt| {
                rt.asm.bt(r9d, 0i32).unwrap();
                rt.asm.$operation(r14, r8).unwrap();
            },
            |rt| {
                rt.asm.bt(r9d, 0i32).unwrap();
                rt.asm.$operation(r14d, r8d).unwrap();
            },
            |rt| {
                rt.asm.bt(r9d, 0i32).unwrap();
                rt.asm.$operation(r14w, r8w).unwrap();
            },
            |rt| {
                rt.asm.bt(r9d, 0i32).unwrap();
                rt.asm.$operation(r14b, r8b).unwrap();
            },
            |rt| {
                rt.asm.bt(r9d, 0i32).unwrap();
                rt.asm.$operation(r14b, r8b).unwrap();
            },
            |rt| {
                rt.asm.bt(r9d, 0i32).unwrap();
                rt.asm.$operation(r14, r8).unwrap();
            },
            |rt| {
                rt.asm.bt(r9d, 0i32).unwrap();
                rt.asm.$operation(r14d, r8d).unwrap();
            },
            |rt| {
                rt.asm.bt(r9d, 0i32).unwrap();
                rt.asm.$operation(r14w, r8w).unwrap();
            },
            |rt| {
                rt.asm.bt(r9d, 0i32).unwrap();
                rt.asm.$operation(r14b, r8b).unwrap();
            },
        );
    };
}

#[macro_export]
macro_rules! arithmetic {
    ($operation:ident, $register:ident, $mask:expr) => {
        use crate::{
            runtime::{FnDef, Runtime},
            vm::utils::{self, scratch},
        };
        use iced_x86::code_asm::*;

        // unsigned char* (unsigned char*)
        pub fn build(rt: &mut Runtime) {
            let mut epilogue = rt.asm.create_label();

            // push r13
            rt.asm.push(r13).unwrap();
            // push r14
            rt.asm.push(r14).unwrap();

            // mov r13, rcx
            rt.asm.mov(r13, rcx).unwrap();

            // al -> width
            utils::bytecode::read_byte(rt, r13, al);

            // load r8
            scratch::load(rt, r12, r8);
            // load r14
            scratch::load(rt, r12, r14);

            $crate::__arithmetic!(rt, $operation, $register, &mut epilogue);

            rt.asm.set_label(&mut epilogue).unwrap();
            {
                // mov rcx, ...
                rt.asm.mov(rcx, $mask).unwrap();
                // pushfq
                rt.asm.pushfq().unwrap();
                // call ...
                rt.asm.call(rt.function_labels[&FnDef::VmFlags]).unwrap();

                // store r14
                scratch::store(rt, r12, r14);

                // mov rax, r13
                rt.asm.mov(rax, r13).unwrap();
                // pop r14
                rt.asm.pop(r14).unwrap();
                // pop r13
                rt.asm.pop(r13).unwrap();
                // ret
                rt.asm.ret().unwrap();
            }
        }
    };
}
pub(crate) use arithmetic;

pub mod add;
pub mod add_carry;
pub mod and;
pub mod bit_scan_reverse;
pub mod bit_test;
pub mod bit_test_complement;
pub mod bit_test_reset;
pub mod bit_test_set;
pub mod byte_swap;
pub mod compare_exchange;
pub mod discard;
pub mod divide;
pub mod exchange;
pub mod exchange_add;
pub mod flags;
pub mod jcc;
pub mod load_address;
pub mod load_immediate;
pub mod load_memory;
pub mod load_register;
pub mod load_vector;
pub mod mul;
pub mod or;
pub mod packed_byte_equal;
pub mod packed_byte_mask;
pub mod pop;
pub mod push;
pub mod ret;
pub mod rol;
pub mod ror;
pub mod sar;
pub mod shl;
pub mod shr;
pub mod store_memory;
pub mod store_register;
pub mod store_vector;
pub mod sub;
pub mod sub_borrow;
pub mod test;
pub mod trailing_zeros;
pub mod vector;
pub mod vector_and;
pub mod vector_and_not;
pub mod vector_or;
pub mod vector_xor;
pub mod xor;

// void (unsigned char*)
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
        (VMOp::LoadVector, FnDef::VmHandlerLoadVector),
        (VMOp::StoreVector, FnDef::VmHandlerStoreVector),
        (VMOp::Add, FnDef::VmHandlerAdd),
        (VMOp::Sub, FnDef::VmHandlerSub),
        (VMOp::AddCarry, FnDef::VmHandlerAddCarry),
        (VMOp::SubBorrow, FnDef::VmHandlerSubBorrow),
        (VMOp::Exchange, FnDef::VmHandlerExchange),
        (VMOp::ExchangeAdd, FnDef::VmHandlerExchangeAdd),
        (VMOp::CompareExchange, FnDef::VmHandlerCompareExchange),
        (VMOp::And, FnDef::VmHandlerAnd),
        (VMOp::Or, FnDef::VmHandlerOr),
        (VMOp::Xor, FnDef::VmHandlerXor),
        (VMOp::Test, FnDef::VmHandlerTest),
        (VMOp::Rol, FnDef::VmHandlerRol),
        (VMOp::Ror, FnDef::VmHandlerRor),
        (VMOp::Shl, FnDef::VmHandlerShl),
        (VMOp::Shr, FnDef::VmHandlerShr),
        (VMOp::Sar, FnDef::VmHandlerSar),
        (VMOp::Mul, FnDef::VmHandlerMul),
        (VMOp::TrailingZeros, FnDef::VmHandlerTrailingZeros),
        (VMOp::BitScanReverse, FnDef::VmHandlerBitScanReverse),
        (VMOp::ByteSwap, FnDef::VmHandlerByteSwap),
        (VMOp::BitTest, FnDef::VmHandlerBitTest),
        (VMOp::BitTestSet, FnDef::VmHandlerBitTestSet),
        (VMOp::BitTestReset, FnDef::VmHandlerBitTestReset),
        (VMOp::BitTestComplement, FnDef::VmHandlerBitTestComplement),
        (VMOp::Push, FnDef::VmHandlerPush),
        (VMOp::Pop, FnDef::VmHandlerPop),
        (VMOp::Discard, FnDef::VmHandlerDiscard),
        (VMOp::VectorAnd, FnDef::VmHandlerVectorAnd),
        (VMOp::VectorOr, FnDef::VmHandlerVectorOr),
        (VMOp::VectorXor, FnDef::VmHandlerVectorXor),
        (VMOp::VectorAndNot, FnDef::VmHandlerVectorAndNot),
        (VMOp::Divide, FnDef::VmHandlerDivide),
    ];

    let mut rng = rand::thread_rng();
    table.shuffle(&mut rng);

    // lea rcx, [...]
    rt.asm
        .lea(rax, ptr(rt.data_labels[&DataDef::VmHandlers]))
        .unwrap();

    rt.with_chain(|rt| {
        // xor rdx, rdx
        rt.asm.xor(rdx, rdx).unwrap();

        for (op, def) in table {
            let key = rt.mark_as_encrypted(rt.function_labels[&def]);
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
            // add r8, rcx
            rt.asm.add(r8, rcx).unwrap();
            // mov [rcx + ...], r8
            rt.asm
                .mov(ptr(rax + rt.mapper.index(op) as i32 * 8), r8)
                .unwrap();
        }
    });
    // ret
    rt.asm.ret().unwrap();
}
