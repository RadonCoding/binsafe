use iced_x86::code_asm::{dword_ptr, ptr, r12, r8, r8d, r9, r9d, rax, rdx};

use crate::{
    runtime::{DataDef, Runtime},
    vm::{
        bytecode::VMReg,
        utils::{self},
    },
};

// unsigned char* (unsigned char*, unsigned int)
pub fn build(rt:  &mut Runtime) {
    // Subtract the image base from the return address:
    // mov r9, rdx
    rt.asm.mov(r9, rdx).unwrap();
    // sub r9, [r12 + ...]
    utils::vreg::reg_sub(rt, r12, VMReg::VImage, r9);

    // Resolve the VM-table entry using the index:
    // xor r8d, r9d
    rt.asm.xor(r8d, r9d).unwrap();
    // and r8d, 0x0FFFFFFF
    rt.asm.and(r8d, 0x0FFFFFFF).unwrap();

    // lea r9, [...]
    rt.asm
        .lea(r9, ptr(rt.data_labels[&DataDef::VmTable]))
        .unwrap();
    // lea r9, [r9 + r8*8]
    rt.asm.lea(r9, ptr(r9 + r8 * 8)).unwrap();

    // Read the displacement and the offset into VM-code from the VM-table:
    // movsxd rax, [r9]
    rt.asm.movsxd(rax, dword_ptr(r9)).unwrap();
    // mov r8d, [r9 + 0x4]
    rt.asm.mov(r8d, ptr(r9 + 0x4)).unwrap();

    // Apply the displacement of the caller stub to the native exit point:
    // mov r9, rdx
    rt.asm.mov(r9, rdx).unwrap();
    // add r9, rax
    rt.asm.add(r9, rax).unwrap();
    // mov [r12 + ...], r9
    utils::vreg::store_reg(rt, r12, r9, VMReg::NExit);

    // Apply the displacement of the caller stub to the native entry point:
    // mov r9, rdx
    rt.asm.mov(r9, rdx).unwrap();
    // sub r9, rax
    rt.asm.sub(r9, rax).unwrap();
    // mov [r12 + ...], r9
    utils::vreg::store_reg(rt, r12, r9, VMReg::NEntry);

    // Compute the block pointer from the offset into VM-code:
    // lea rax, [...]
    rt.asm
        .lea(rax, ptr(rt.data_labels[&DataDef::VmCode]))
        .unwrap();
    // add rax, r8
    rt.asm.add(rax, r8).unwrap();

    // ret
    rt.asm.ret().unwrap();
}
