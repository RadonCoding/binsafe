#[macro_export]
macro_rules! __arithmetic {
    ($rt:expr, $operation:ident, r8, $epilogue:expr) => {
        $crate::vm::utils::width::dispatch(
            $rt,
            rax,
            $epilogue,
            Some(Box::new(|rt| {
                rt.asm.$operation(r14, r8).unwrap();
            })),
            Some(Box::new(|rt| {
                rt.asm.$operation(r14d, r8d).unwrap();
            })),
            Some(Box::new(|rt| {
                rt.asm.$operation(r14w, r8w).unwrap();
            })),
            None,
            Some(Box::new(|rt| {
                rt.asm.$operation(r14b, r8b).unwrap();
            })),
            None,
            None,
            None,
            None,
            None,
            None,
        );
    };
    ($rt:expr, $operation:ident, shift, $epilogue:expr) => {
        $rt.asm.mov(cl, r8b).unwrap();
        $crate::vm::utils::width::dispatch(
            $rt,
            rax,
            $epilogue,
            Some(Box::new(|rt| {
                rt.asm.$operation(r14, cl).unwrap();
            })),
            Some(Box::new(|rt| {
                rt.asm.$operation(r14d, cl).unwrap();
            })),
            Some(Box::new(|rt| {
                rt.asm.$operation(r14w, cl).unwrap();
            })),
            None,
            Some(Box::new(|rt| {
                rt.asm.$operation(r14b, cl).unwrap();
            })),
            None,
            None,
            None,
            None,
            None,
            None,
        );
    };
    ($rt:expr, $operation:ident, bitscan, $epilogue:expr) => {
        $crate::vm::utils::width::dispatch(
            $rt,
            rax,
            $epilogue,
            Some(Box::new(|rt| {
                rt.asm.$operation(r14, r8).unwrap();
            })),
            Some(Box::new(|rt| {
                rt.asm.$operation(r14d, r8d).unwrap();
            })),
            Some(Box::new(|rt| {
                rt.asm.$operation(r14w, r8w).unwrap();
            })),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
    };
    ($rt:expr, $operation:ident, carry, $epilogue:expr) => {
        // r9d -> flags
        $crate::vm::utils::vreg::load_reg32($rt, r12, $crate::vm::bytecode::VMReg::Flags, r9d);
        $crate::vm::utils::width::dispatch(
            $rt,
            rax,
            $epilogue,
            Some(Box::new(|rt| {
                rt.asm.bt(r9d, 0i32).unwrap();
                rt.asm.$operation(r14, r8).unwrap();
            })),
            Some(Box::new(|rt| {
                rt.asm.bt(r9d, 0i32).unwrap();
                rt.asm.$operation(r14d, r8d).unwrap();
            })),
            Some(Box::new(|rt| {
                rt.asm.bt(r9d, 0i32).unwrap();
                rt.asm.$operation(r14w, r8w).unwrap();
            })),
            None,
            Some(Box::new(|rt| {
                rt.asm.bt(r9d, 0i32).unwrap();
                rt.asm.$operation(r14b, r8b).unwrap();
            })),
            None,
            None,
            None,
            None,
            None,
            None,
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

            // eax -> width
            utils::bytecode::read_byte_zx(rt, r13, eax);

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
pub mod div;
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
pub mod store_extend;
pub mod store_memory;
pub mod store_merge;
pub mod store_register;
pub mod sub;
pub mod sub_borrow;
pub mod test;
pub mod trailing_zeros;
pub mod vector;
pub mod vector_add;
pub mod vector_and;
pub mod vector_and_not;
pub mod vector_or;
pub mod vector_sub;
pub mod vector_xor;
pub mod xor;
