use iced_x86::code_asm::{dword_ptr, edx, ptr, r12, r8, r8d, rax, rcx, rdx};

use crate::{
    runtime::{DataDef, Runtime},
    vm::{
        bytecode::VMReg,
        utils::{self},
    },
};

// unsigned char* (unsigned char*, unsigned int)
pub fn build(rt: &mut Runtime) {
    // Subtract the image base from the return address:
    // mov r8, rcx
    rt.asm.mov(r8, rcx).unwrap();
    // sub r8, [r12 + ...]
    utils::vreg::reg_sub(rt, r12, VMReg::VImage, r8);

    // Resolve the table entry using the index:
    // xor edx, r8d
    rt.asm.xor(edx, r8d).unwrap();
    // and edx, 0x0FFFFFFF
    rt.asm.and(edx, 0x0FFFFFFF).unwrap();
    // sub edx, ...
    rt.asm.sub(edx, rt.keys.addend as u32 as i32).unwrap();
    // imul edx, edx, ...
    rt.asm
        .imul_3(
            edx,
            edx,
            crate::utils::invert_multiplier(rt.keys.multiplier) as u32 as i32,
        )
        .unwrap();
    // and edx, 0x0FFFFFFF
    rt.asm.and(edx, 0x0FFFFFFF).unwrap();

    // lea r8, [...]
    rt.asm
        .lea(r8, ptr(rt.data_labels[&DataDef::VmTable]))
        .unwrap();
    // lea rax, [rdx + rdx*2]
    rt.asm.lea(rax, ptr(rdx + rdx * 2)).unwrap();
    // lea r8, [r8 + rax*4]
    rt.asm.lea(r8, ptr(r8 + rax * 4)).unwrap();

    // Apply the exit displacement of the caller stub to the return address:
    // movsxd rax, [r8]
    rt.asm.movsxd(rax, dword_ptr(r8)).unwrap();
    // add rax, rcx
    rt.asm.add(rax, rcx).unwrap();
    // mov [r12 + ...], rax
    utils::vreg::store_reg(rt, r12, rax, VMReg::NExit);

    // Apply the entry displacement of the caller stub to the return address:
    // movsxd rax, [r8 + 0x4]
    rt.asm.movsxd(rax, dword_ptr(r8 + 0x4)).unwrap();
    // add rax, rcx
    rt.asm.add(rax, rcx).unwrap();
    // mov [r12 + ...], rax
    utils::vreg::store_reg(rt, r12, rax, VMReg::NEntry);

    // Read the offset into bytecode from the table:
    // mov edx, [r8 + 0x8]
    rt.asm.mov(edx, ptr(r8 + 0x8)).unwrap();

    // Compute the block pointer from the offset into bytecode:
    // lea rax, [...]
    rt.asm
        .lea(rax, ptr(rt.data_labels[&DataDef::VmCodeStart]))
        .unwrap();
    // movsxd rcx, [rax]
    rt.asm.movsxd(rcx, ptr(rax)).unwrap();
    // add rax, rcx
    rt.asm.add(rax, rcx).unwrap();
    // add rax, rdx
    rt.asm.add(rax, rdx).unwrap();

    // ret
    rt.asm.ret().unwrap();
}
