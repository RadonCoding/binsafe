use iced_x86::code_asm::{eax, ptr, r12, r8b, r9, r9d, rax, rcx, xmm0, ymm0};

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMReg,
        utils::{self, scratch},
    },
};

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // r8b -> width
    utils::bytecode::read_byte(rt, rcx, r8b);
    // r9d -> source
    utils::bytecode::read_byte_zx(rt, rcx, r9d);

    // shl r9, 0x5
    rt.asm.shl(r9, 0x5).unwrap();

    // mov rax, [r12 + ...]
    utils::vreg::load_reg(rt, r12, VMReg::VVector, rax);

    utils::width::dispatch_lane_or_vector(
        rt,
        r8b,
        &mut epilogue,
        |rt| {
            // mov eax, [rax + r9]
            rt.asm.mov(eax, ptr(rax + r9)).unwrap();
            // store rax
            scratch::store(rt, r12, rax);
        },
        |rt| {
            // mov rax, [rax + r9]
            rt.asm.mov(rax, ptr(rax + r9)).unwrap();
            // store rax
            scratch::store(rt, r12, rax);
        },
        |rt| {
            // movups xmm0, [rax + r9]
            rt.asm.movups(xmm0, ptr(rax + r9)).unwrap();
            // store xmm0
            scratch::store_128(rt, r12, xmm0);
        },
        |rt| {
            // vmovups ymm0, [rax + r9]
            rt.asm.vmovups(ymm0, ptr(rax + r9)).unwrap();
            // store ymm0
            scratch::store_256(rt, r12, ymm0);
        },
    );

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, rcx
        rt.asm.mov(rax, rcx).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
