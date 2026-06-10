use iced_x86::code_asm::{eax, ecx, ptr, rax, CodeLabel};

use crate::{
    runtime::{DataDef, Runtime},
    vm::{bytecode::VMReg, utils, VECTORS_TO_NATIVE},
};

pub fn capture(rt:  &mut Runtime) {
    let mut sse = rt.asm.create_label();

    detect(rt, sse);

    base(rt);

    for (vec, ymm, _) in VECTORS_TO_NATIVE {
        // vmovups [rax + ...], ...
        utils::vvec::store_256(rt, rax, *ymm, *vec);
    }
    // ret
    rt.asm.ret().unwrap();

    rt.asm.set_label(&mut sse).unwrap();
    {
        base(rt);

        for (vec, _, xmm) in VECTORS_TO_NATIVE {
            // movups [rax + ...], ...
            utils::vvec::store_128(rt, rax, *xmm, *vec);
        }
        // ret
        rt.asm.ret().unwrap();
    }
}

pub fn restore(rt:  &mut Runtime) {
    let mut sse = rt.asm.create_label();

    detect(rt, sse);

    base(rt);

    for (src, dst, _) in VECTORS_TO_NATIVE {
        // vmovups ..., [rax + ...]
        utils::vvec::load_256(rt, rax, *src, *dst);
    }
    // ret
    rt.asm.ret().unwrap();

    rt.asm.set_label(&mut sse).unwrap();
    {
        base(rt);

        for (src, _, dst) in VECTORS_TO_NATIVE {
            // movups ..., [rax + ...]
            utils::vvec::load_128(rt, rax, *src, *dst);
        }
        // ret
        rt.asm.ret().unwrap();
    }
}

fn base(rt:  &mut Runtime) {
    // mov eax, [...]
    rt.asm
        .mov(eax, ptr(rt.data_labels[&DataDef::VmRegistersTlsIndex]))
        .unwrap();
    // mov rax, gs:[0x1480 + rax*8]
    rt.asm.mov(rax, ptr(0x1480 + rax * 8).gs()).unwrap();
    // mov rax, [rax + ...]
    utils::vreg::load_reg(rt, rax, VMReg::VVector, rax);
}

fn detect(rt:  &mut Runtime, sse: CodeLabel) {
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
}
