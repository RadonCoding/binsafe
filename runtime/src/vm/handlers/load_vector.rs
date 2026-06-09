use iced_x86::code_asm::{al, eax, ptr, r8, r9, r9d, rax, rcx, rdx, xmm0, ymm0};

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{VMReg, VMWidth},
        utils::{self, scratch},
    },
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();
    let mut narrow32 = rt.asm.create_label();
    let mut narrow64 = rt.asm.create_label();

    // al -> width
    utils::bytecode::read_byte(rt, rdx, al);

    // r9d -> source
    utils::bytecode::read_byte_zx(rt, rdx, r9d);
    // shl r9, 0x5
    rt.asm.shl(r9, 0x5).unwrap();

    // mov r8, [rcx + ...]
    utils::vreg::load_reg(rt, rcx, VMReg::VVector, r8);

    // cmp al, ...
    rt.asm
        .cmp(al, rt.mapper.index(VMWidth::Lower32) as i32)
        .unwrap();
    // je ...
    rt.asm.je(narrow32).unwrap();
    // cmp al, ...
    rt.asm
        .cmp(al, rt.mapper.index(VMWidth::Lower64) as i32)
        .unwrap();
    // je ...
    rt.asm.je(narrow64).unwrap();

    utils::width::dispatch_vector(
        rt,
        al,
        &mut epilogue,
        |rt| {
            // movups xmm0, [r8 + r9]
            rt.asm.movups(xmm0, ptr(r8 + r9)).unwrap();
            // store xmm0
            scratch::store_128(rt, rcx, xmm0);
        },
        |rt| {
            // vmovups ymm0, [r8 + r9]
            rt.asm.vmovups(ymm0, ptr(r8 + r9)).unwrap();
            // store ymm0
            scratch::store_256(rt, rcx, ymm0);
        },
    );

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }

    rt.asm.set_label(&mut narrow32).unwrap();
    {
        // mov eax, [r8 + r9]
        rt.asm.mov(eax, ptr(r8 + r9)).unwrap();
        // store rax
        scratch::store(rt, rcx, rax);
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut narrow64).unwrap();
    {
        // mov rax, [r8 + r9]
        rt.asm.mov(rax, ptr(r8 + r9)).unwrap();
        // store rax
        scratch::store(rt, rcx, rax);
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }
}
