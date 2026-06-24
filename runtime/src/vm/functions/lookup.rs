use iced_x86::code_asm::{dword_ptr, edx, ptr, r12, r8, r8d, rax, rcx, rdx};

use crate::{
    runtime::{DataDef, Runtime},
    vm::{
        bytecode::VMReg,
        utils::{self},
    },
    VM_DISPATCH_SIZE,
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

    // lea r8, [...]
    rt.asm
        .lea(r8, ptr(rt.data_labels[&DataDef::VmTable]))
        .unwrap();
    // lea r8, [r8 + rdx*8]
    rt.asm.lea(r8, ptr(r8 + rdx * 8)).unwrap();

    // Read the displacement and the offset into bytecode from the table:
    // movsxd rax, [r8]
    rt.asm.movsxd(rax, dword_ptr(r8)).unwrap();
    // mov edx, [r8 + 0x4]
    rt.asm.mov(edx, ptr(r8 + 0x4)).unwrap();

    // Apply the displacement of the caller stub to the native exit point:
    // mov r8, rcx
    rt.asm.mov(r8, rcx).unwrap();
    // add r8, rax
    rt.asm.add(r8, rax).unwrap();
    // mov [r12 + ...], r8
    utils::vreg::store_reg(rt, r12, r8, VMReg::NExit);

    // Apply the displacement of the caller stub to the native entry point:
    // mov r8, rcx
    rt.asm.mov(r8, rcx).unwrap();
    // sub r8, ...
    rt.asm.sub(r8, VM_DISPATCH_SIZE as i32).unwrap();
    // mov [r12 + ...], r8
    utils::vreg::store_reg(rt, r12, r8, VMReg::NEntry);

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
