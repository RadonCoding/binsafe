use iced_x86::code_asm::{al, eax, ptr, r8, r9, r9d, rax, rcx, rdx, xmm0, ymm0};

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMReg,
        utils::{self, scratch},
    },
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // al -> width
    utils::bytecode::read_byte(rt, rdx, al);

    // r9d -> destination
    utils::bytecode::read_byte_zx(rt, rdx, r9d);
    // shl r9, 0x5
    rt.asm.shl(r9, 0x5).unwrap();

    // mov r8, [rcx + ...]
    utils::vreg::load_reg(rt, rcx, VMReg::VVector, r8);

    utils::width::dispatch_lane_or_vector(
        rt,
        al,
        &mut epilogue,
        |rt| {
            // load rax
            scratch::load(rt, rcx, rax);
            // mov [r8 + r9], eax
            rt.asm.mov(ptr(r8 + r9), eax).unwrap();
        },
        |rt| {
            // load rax
            scratch::load(rt, rcx, rax);
            // mov [r8 + r9], rax
            rt.asm.mov(ptr(r8 + r9), rax).unwrap();
        },
        |rt| {
            // load xmm0
            scratch::load_128(rt, rcx, xmm0);
            // movups [r8 + r9], xmm0
            rt.asm.movups(ptr(r8 + r9), xmm0).unwrap();
        },
        |rt| {
            // load ymm0
            scratch::load_256(rt, rcx, ymm0);
            // vmovups [r8 + r9], ymm0
            rt.asm.vmovups(ptr(r8 + r9), ymm0).unwrap();
        },
    );

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
