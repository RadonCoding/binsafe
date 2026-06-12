use iced_x86::code_asm::{edx, ptr, r12, r13, r8, r9, r9b, r9d, r9w, rax, rcx, rdx};

use crate::{
    runtime::{FnDef, Runtime},
    vm::{
        bytecode::VMFlag,
        utils::{self, scratch},
    },
};

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // push r13
    rt.asm.push(r13).unwrap();
    // mov r13, rcx
    rt.asm.mov(r13, rcx).unwrap();

    // edx -> width
    utils::bytecode::read_byte_zx(rt, r13, edx);

    // load r8
    scratch::load(rt, r12, r8);
    // load r9
    scratch::load(rt, r12, r9);
    // load rax
    scratch::load(rt, r12, rax);

    utils::width::dispatch(
        rt,
        rdx,
        &mut epilogue,
        Some(Box::new(|rt| {
            // lock cmpxchg [r8], r9
            rt.asm.lock().cmpxchg(ptr(r8), r9).unwrap();
        })),
        Some(Box::new(|rt| {
            // lock cmpxchg [r8], r9d
            rt.asm.lock().cmpxchg(ptr(r8), r9d).unwrap();
        })),
        Some(Box::new(|rt| {
            // lock cmpxchg [r8], r9w
            rt.asm.lock().cmpxchg(ptr(r8), r9w).unwrap();
        })),
        None,
        Some(Box::new(|rt| {
            // lock cmpxchg [r8], r9b
            rt.asm.lock().cmpxchg(ptr(r8), r9b).unwrap();
        })),
        None,
        None,
        None,
        None,
        None,
        None,
    );

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // pushfq
        rt.asm.pushfq().unwrap();

        // store rax
        scratch::store(rt, r12, rax);

        // mov rcx, ...
        rt.asm
            .mov(
                rcx,
                VMFlag::Carry.bit64()
                    | VMFlag::Parity.bit64()
                    | VMFlag::Auxiliary.bit64()
                    | VMFlag::Zero.bit64()
                    | VMFlag::Sign.bit64()
                    | VMFlag::Overflow.bit64(),
            )
            .unwrap();
        // call ...
        rt.asm.call(rt.function_labels[&FnDef::VmFlags]).unwrap();

        // mov rax, r13
        rt.asm.mov(rax, r13).unwrap();
        // pop r13
        rt.asm.pop(r13).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
