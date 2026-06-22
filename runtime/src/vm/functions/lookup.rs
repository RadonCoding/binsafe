use iced_x86::code_asm::{dword_ptr, edx, ptr, r12, r9, r9d, rax, rcx, rdx};

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
    // mov r9, rcx
    rt.asm.mov(r9, rcx).unwrap();
    // sub r9, [r12 + ...]
    utils::vreg::reg_sub(rt, r12, VMReg::VImage, r9);

    // Resolve the table entry using the index:
    // xor edx, r9d
    rt.asm.xor(edx, r9d).unwrap();
    // and edx, 0x0FFFFFFF
    rt.asm.and(edx, 0x0FFFFFFF).unwrap();

    // lea r9, [...]
    rt.asm
        .lea(r9, ptr(rt.data_labels[&DataDef::VmTable]))
        .unwrap();
    // lea r9, [r9 + rdx*8]
    rt.asm.lea(r9, ptr(r9 + rdx * 8)).unwrap();

    // Read the displacement and the offset into bytecode from the table:
    // movsxd rax, [r9]
    rt.asm.movsxd(rax, dword_ptr(r9)).unwrap();
    // mov edx, [r9 + 0x4]
    rt.asm.mov(edx, ptr(r9 + 0x4)).unwrap();

    // Apply the displacement of the caller stub to the native exit point:
    // mov r9, rcx
    rt.asm.mov(r9, rcx).unwrap();
    // add r9, rax
    rt.asm.add(r9, rax).unwrap();
    // mov [r12 + ...], r9
    utils::vreg::store_reg(rt, r12, r9, VMReg::NExit);

    // Apply the displacement of the caller stub to the native entry point:
    // mov r9, rcx
    rt.asm.mov(r9, rcx).unwrap();
    // sub r9, rax
    rt.asm.sub(r9, rax).unwrap();
    // mov [r12 + ...], r9
    utils::vreg::store_reg(rt, r12, r9, VMReg::NEntry);

    // Compute the block pointer from the offset into bytecode:
    // lea rax, [...]
    rt.asm
        .lea(rax, ptr(rt.data_labels[&DataDef::VmCode]))
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
