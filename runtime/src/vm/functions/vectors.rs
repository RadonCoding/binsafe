use iced_x86::code_asm::{al, byte_ptr, eax, ecx, r12, r13, r14, rax, rbx, rcx, rdx, xmm0, ymm0};

use crate::{
    runtime::{BoolDef, FnDef, Runtime},
    vm::{bytecode::VMReg, utils, VECTORS_TO_NATIVE},
};

pub fn avx(rt: &mut Runtime) {
    let mut sse = rt.asm.create_label();
    let mut check = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push rbx
    rt.asm.push(rbx).unwrap();

    // cmp [...], 0x0
    rt.asm
        .cmp(byte_ptr(rt.bool_labels[&BoolDef::HasAvx]), 0x0)
        .unwrap();
    // je ...
    rt.asm.je(check).unwrap();

    // cmp [...], 0x1
    rt.asm
        .cmp(byte_ptr(rt.bool_labels[&BoolDef::HasAvx]), 0x1)
        .unwrap();
    // sete al
    rt.asm.sete(al).unwrap();
    // movzx rax, al
    rt.asm.movzx(rax, al).unwrap();
    // jmp ...
    rt.asm.jmp(epilogue).unwrap();

    rt.asm.set_label(&mut check).unwrap();
    {
        // mov eax, 0x1
        rt.asm.mov(eax, 0x1).unwrap();
        // cpuid
        rt.asm.cpuid().unwrap();
        // test ecx, 0x08000000 -> OSXSAVE
        rt.asm.test(ecx, 0x08000000).unwrap();
        // jz ...
        rt.asm.jz(sse).unwrap();
        // test ecx, 0x10000000 -> AVX
        rt.asm.test(ecx, 0x10000000).unwrap();
        // jz ...
        rt.asm.jz(sse).unwrap();
        // xor ecx, ecx
        rt.asm.xor(ecx, ecx).unwrap();
        // xgetbv
        rt.asm.xgetbv().unwrap();
        // and eax, 0x6
        rt.asm.and(eax, 0x6).unwrap();
        // cmp eax, 0x6
        rt.asm.cmp(eax, 0x6).unwrap();
        // jne ...
        rt.asm.jne(sse).unwrap();

        // mov [...], 0x1
        rt.asm
            .mov(byte_ptr(rt.bool_labels[&BoolDef::HasAvx]), 0x1)
            .unwrap();
        // mov eax, 0x1
        rt.asm.mov(eax, 0x1).unwrap();
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut sse).unwrap();
    {
        // mov [...], 0xFF
        rt.asm
            .mov(byte_ptr(rt.bool_labels[&BoolDef::HasAvx]), 0xFFu32)
            .unwrap();
        // xor eax, eax
        rt.asm.xor(eax, eax).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // pop rbx
        rt.asm.pop(rbx).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}

pub fn capture(rt: &mut Runtime) {
    let mut sse = rt.asm.create_label();

    // push r13
    rt.asm.push(r13).unwrap();
    // mov r13, rcx
    rt.asm.mov(r13, rcx).unwrap();

    // call ...
    rt.asm
        .call(rt.function_labels[&FnDef::VmVectorsAvx])
        .unwrap();
    // test rax, rax
    rt.asm.test(rax, rax).unwrap();
    // jz ...
    rt.asm.jz(sse).unwrap();

    for (vec, ymm, _) in VECTORS_TO_NATIVE {
        // vmovups [rax + ...], ...
        utils::vvec::store_256(rt, r13, *ymm, *vec);
    }
    // pop r13
    rt.asm.pop(r13).unwrap();
    // ret
    rt.asm.ret().unwrap();

    rt.asm.set_label(&mut sse).unwrap();
    {
        for (vec, _, xmm) in VECTORS_TO_NATIVE {
            // movups [rax + ...], ...
            utils::vvec::store_128(rt, r13, *xmm, *vec);
        }
        // pop r13
        rt.asm.pop(r13).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}

pub fn restore(rt: &mut Runtime) {
    let mut sse = rt.asm.create_label();

    // call ...
    rt.asm
        .call(rt.function_labels[&FnDef::VmVectorsAvx])
        .unwrap();
    // test rax, rax
    rt.asm.test(rax, rax).unwrap();
    // jz ...
    rt.asm.jz(sse).unwrap();

    // mov rax, [r12 + ...]
    utils::vreg::load_reg(rt, r12, VMReg::VVector, rax);

    for (src, dst, _) in VECTORS_TO_NATIVE {
        // vmovups ..., [rax + ...]
        utils::vvec::load_256(rt, rax, *src, *dst);
    }
    // ret
    rt.asm.ret().unwrap();

    rt.asm.set_label(&mut sse).unwrap();
    {
        // mov rax, [r12 + ...]
        utils::vreg::load_reg(rt, r12, VMReg::VVector, rax);

        for (src, _, dst) in VECTORS_TO_NATIVE {
            // movups ..., [rax + ...]
            utils::vvec::load_128(rt, rax, *src, *dst);
        }
        // ret
        rt.asm.ret().unwrap();
    }
}

pub fn copy(rt: &mut Runtime) {
    let mut sse = rt.asm.create_label();

    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();
    // mov r13, rcx
    rt.asm.mov(r13, rcx).unwrap();
    // mov r14, rdx
    rt.asm.mov(r14, rdx).unwrap();

    // call ...
    rt.asm
        .call(rt.function_labels[&FnDef::VmVectorsAvx])
        .unwrap();
    // test rax, rax
    rt.asm.test(rax, rax).unwrap();
    // jz ...
    rt.asm.jz(sse).unwrap();

    for (vec, ymm, _) in VECTORS_TO_NATIVE {
        // vmovups ymm0, [r13 + ...]
        utils::vvec::load_256(rt, r13, *vec, ymm0);
        // vmovups [r14 + ...], ymm0
        utils::vvec::store_256(rt, r14, *ymm, *vec);
    }
    // pop r14
    rt.asm.pop(r14).unwrap();
    // pop r13
    rt.asm.pop(r13).unwrap();
    // ret
    rt.asm.ret().unwrap();

    rt.asm.set_label(&mut sse).unwrap();
    {
        for (vec, _, xmm) in VECTORS_TO_NATIVE {
            // movups xmm0, [r13 + ...]
            utils::vvec::load_128(rt, r13, *vec, xmm0);
            // movups [r14 + ...], xmm0
            utils::vvec::store_128(rt, r14, *xmm, *vec);
        }
        // pop r14
        rt.asm.pop(r14).unwrap();
        // pop r13
        rt.asm.pop(r13).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
