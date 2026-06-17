use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{VMFlag, VMReg},
        utils::{self, scratch},
    },
};
use iced_x86::code_asm::*;

pub fn build(rt: &mut Runtime) {
    let mut compute_flags = rt.asm.create_label();

    let mut carry = rt.asm.create_label();
    let mut overflow = rt.asm.create_label();
    let mut sign = rt.asm.create_label();
    let mut zero = rt.asm.create_label();
    let mut auxfiliary = rt.asm.create_label();
    let mut parity = rt.asm.create_label();

    let mut commit_flags = rt.asm.create_label();

    let mut epilogue = rt.asm.create_label();

    let cf = VMFlag::Carry.bit64() as i64;
    let of = VMFlag::Overflow.bit64() as i64;
    let sf = VMFlag::Sign.bit64() as i64;
    let zf = VMFlag::Zero.bit64() as i64;
    let af = VMFlag::Auxiliary.bit64() as i64;
    let pf = VMFlag::Parity.bit64() as i64;
    let mask = cf | of | sf | zf | af | pf;

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
    // load r9
    scratch::load(rt, r12, r9);

    utils::width::dispatch(
        rt,
        rax,
        &mut epilogue,
        Some(Box::new(move |rt| {
            // mov r14, r9
            rt.asm.mov(r14, r9).unwrap();
            // add r14, r8
            rt.asm.add(r14, r8).unwrap();
            // mov rcx, r14
            rt.asm.mov(rcx, r14).unwrap();
            // mov rdx, r9
            rt.asm.mov(rdx, r9).unwrap();
            // mov r8, r8
            rt.asm.mov(r8, r8).unwrap();
            // mov r9, 0x8000000000000000
            rt.asm.mov(r9, 0x8000000000000000u64 as i64).unwrap();
            // call ...
            rt.asm.call(compute_flags).unwrap();
        })),
        Some(Box::new(move |rt| {
            // mov r14d, r9d
            rt.asm.mov(r14d, r9d).unwrap();
            // add r14d, r8d
            rt.asm.add(r14d, r8d).unwrap();
            // mov r14d, r14d
            rt.asm.mov(r14d, r14d).unwrap();
            // mov rcx, r14
            rt.asm.mov(rcx, r14).unwrap();
            // mov rdx, r9
            rt.asm.mov(rdx, r9).unwrap();
            // mov r8, r8
            rt.asm.mov(r8, r8).unwrap();
            // mov r9, 0x80000000
            rt.asm.mov(r9, 0x80000000u64 as i64).unwrap();
            // call ...
            rt.asm.call(compute_flags).unwrap();
        })),
        None,
        Some(Box::new(move |rt| {
            // mov r14w, r9w
            rt.asm.mov(r14w, r9w).unwrap();
            // add r14w, r8w
            rt.asm.add(r14w, r8w).unwrap();
            // movzx r14, r14w
            rt.asm.movzx(r14, r14w).unwrap();
            // mov rcx, r14
            rt.asm.mov(rcx, r14).unwrap();
            // mov rdx, r9
            rt.asm.mov(rdx, r9).unwrap();
            // mov r8, r8
            rt.asm.mov(r8, r8).unwrap();
            // mov r9, 0x8000
            rt.asm.mov(r9, 0x8000i64).unwrap();
            // call ...
            rt.asm.call(compute_flags).unwrap();
        })),
        None,
        Some(Box::new(move |rt| {
            // mov r14b, r9b
            rt.asm.mov(r14b, r9b).unwrap();
            // add r14b, r8b
            rt.asm.add(r14b, r8b).unwrap();
            // movzx r14, r14b
            rt.asm.movzx(r14, r14b).unwrap();
            // mov rcx, r14
            rt.asm.mov(rcx, r14).unwrap();
            // mov rdx, r9
            rt.asm.mov(rdx, r9).unwrap();
            // mov r8, r8
            rt.asm.mov(r8, r8).unwrap();
            // mov r9, 0x80
            rt.asm.mov(r9, 0x80i64).unwrap();
            // call ...
            rt.asm.call(compute_flags).unwrap();
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

    // rcx=out, rdx=lhs, r8=rhs, r9=msb
    rt.asm.set_label(&mut compute_flags).unwrap();
    {
        // push r13
        rt.asm.push(r13).unwrap();
        // push r14
        rt.asm.push(r14).unwrap();
        // push r15
        rt.asm.push(r15).unwrap();

        // xor r13d, r13d
        rt.asm.xor(r13d, r13d).unwrap();

        rt.asm.set_label(&mut carry).unwrap();
        {
            // cmp rcx, rdx
            rt.asm.cmp(rcx, rdx).unwrap();
            // jae ...
            rt.asm.jae(overflow).unwrap();
            // mov r14, ...
            rt.asm.mov(r14, cf).unwrap();
            // or r13, r14
            rt.asm.or(r13, r14).unwrap();
        }

        rt.asm.set_label(&mut overflow).unwrap();
        {
            // mov r14, r8
            rt.asm.mov(r14, r8).unwrap();
            // xor r14, rcx
            rt.asm.xor(r14, rcx).unwrap();
            // mov rax, r8
            rt.asm.mov(rax, rdx).unwrap();
            // xor rax, rcx
            rt.asm.xor(rax, rcx).unwrap();
            // and r14, rax
            rt.asm.and(r14, rax).unwrap();
            // mov rax, ...
            rt.asm.mov(rax, r9).unwrap();
            // test r14, rax
            rt.asm.test(r14, rax).unwrap();
            // je ...
            rt.asm.je(sign).unwrap();
            // mov r14, ...
            rt.asm.mov(r14, of).unwrap();
            // or r13, r14
            rt.asm.or(r13, r14).unwrap();
        }

        rt.asm.set_label(&mut sign).unwrap();
        {
            // mov rax, ...
            rt.asm.mov(rax, r9).unwrap();
            // test rcx, rax
            rt.asm.test(rcx, rax).unwrap();
            // je ...
            rt.asm.je(zero).unwrap();
            // mov r14, ...
            rt.asm.mov(r14, sf).unwrap();
            // or r13, r14
            rt.asm.or(r13, r14).unwrap();
        }

        rt.asm.set_label(&mut zero).unwrap();
        {
            // test rcx, rcx
            rt.asm.test(rcx, rcx).unwrap();
            // jne ...
            rt.asm.jne(auxfiliary).unwrap();
            // mov r14, ...
            rt.asm.mov(r14, zf).unwrap();
            // or r13, r14
            rt.asm.or(r13, r14).unwrap();
        }

        rt.asm.set_label(&mut auxfiliary).unwrap();
        {
            // mov r14, r8
            rt.asm.mov(r14, r8).unwrap();
            // xor r14, rdx
            rt.asm.xor(r14, rdx).unwrap();
            // xor r14, rcx
            rt.asm.xor(r14, rcx).unwrap();
            // test r14, 0x10
            rt.asm.test(r14, 0x10i32).unwrap();
            // je ...
            rt.asm.je(parity).unwrap();
            // mov r14, ...
            rt.asm.mov(r14, af).unwrap();
            // or r13, r14
            rt.asm.or(r13, r14).unwrap();
        }

        rt.asm.set_label(&mut parity).unwrap();
        {
            // mov r14, rcx
            rt.asm.mov(r14, rcx).unwrap();
            // and r14, 0xFF
            rt.asm.and(r14, 0xFF).unwrap();
            // popcnt r14, r14
            rt.asm.popcnt(r14, r14).unwrap();
            // test r14, 0x1
            rt.asm.test(r14, 0x1).unwrap();
            // jne ...
            rt.asm.jne(commit_flags).unwrap();
            // mov r14, ...
            rt.asm.mov(r14, pf).unwrap();
            // or r13, r14
            rt.asm.or(r13, r14).unwrap();
        }

        rt.asm.set_label(&mut commit_flags).unwrap();
        {
            // mov eax, [r12 + ...]
            utils::vreg::load_reg32(rt, r12, VMReg::Flags, eax);
            // mov r14, ...
            rt.asm.mov(r14, !mask).unwrap();
            // and rax, r14
            rt.asm.and(rax, r14).unwrap();
            // mov r14, ...
            rt.asm.mov(r14, mask).unwrap();
            // and r13, r14
            rt.asm.and(r13, r14).unwrap();
            // or rax, r13
            rt.asm.or(rax, r13).unwrap();
            // mov [r12 + ...], eax
            utils::vreg::store_reg32(rt, r12, eax, VMReg::Flags);
        }

        // pop r15
        rt.asm.pop(r15).unwrap();
        // pop r14
        rt.asm.pop(r14).unwrap();
        // pop r13
        rt.asm.pop(r13).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
