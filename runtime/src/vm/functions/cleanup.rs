use iced_x86::code_asm::{ptr, qword_ptr, r12, r12d, rcx};

use crate::{
    runtime::{DataDef, FnDef, Runtime},
    vm::{bytecode::VMReg, utils},
};

pub fn build(rt: &mut Runtime) {
    let mut skip_shadow = rt.asm.create_label();

    // push r12
    rt.asm.push(r12).unwrap();

    // mov r12d, [...]
    rt.asm
        .mov(r12d, ptr(rt.data_labels[&DataDef::VmRegistersTlsIndex]))
        .unwrap();
    // mov r12, gs:[0x1480 + r12*8]
    rt.asm.mov(r12, ptr(0x1480 + r12 * 8).gs()).unwrap();

    // mov rcx, [r12 + ...]
    utils::vreg::load_reg(rt, r12, VMReg::VShadow, rcx);
    // test rcx, rcx
    rt.asm.test(rcx, rcx).unwrap();
    // jz ...
    rt.asm.jz(skip_shadow).unwrap();

    // call ...
    rt.asm
        .call(rt.function_labels[&FnDef::VmContextDelete])
        .unwrap();

    rt.asm.set_label(&mut skip_shadow).unwrap();

    // mov rcx, r12
    rt.asm.mov(rcx, r12).unwrap();
    // call ...
    rt.asm
        .call(rt.function_labels[&FnDef::VmContextDelete])
        .unwrap();

    // mov r12d, [...]
    rt.asm
        .mov(r12d, ptr(rt.data_labels[&DataDef::VmRegistersTlsIndex]))
        .unwrap();
    // mov gs:[0x1480 + r12*8], 0x0
    rt.asm.mov(qword_ptr(0x1480 + r12 * 8).gs(), 0x0).unwrap();

    #[cfg(debug_assertions)]
    {
        use iced_x86::code_asm::{r12, r13, r8, r8d, rax, rdx, rsp};

        use crate::{runtime::ImportDef, VM_DEBUG_SIZE};

        // push r13
        rt.asm.push(r13).unwrap();

        // sub rsp, 0x20
        rt.asm.sub(rsp, 0x20).unwrap();

        // mov rcx, [...]; call ...
        rt.resolve(ImportDef::GetProcessHeap);
        // call rax
        rt.asm.call(rax).unwrap();
        // mov r12, rax
        rt.asm.mov(r12, rax).unwrap();

        // mov rcx, [...]; call ...
        rt.resolve(ImportDef::RtlFreeHeap);
        // mov r13, rax
        rt.asm.mov(r13, rax).unwrap();

        // mov rcx, r12
        rt.asm.mov(rcx, r12).unwrap();
        // xor rdx, rdx
        rt.asm.xor(rdx, rdx).unwrap();
        // mov r8d, [...]
        rt.asm
            .mov(r8d, ptr(rt.data_labels[&DataDef::VmDebugTlsIndex]))
            .unwrap();
        // mov r8, gs:[0x1480 + r8*8]
        rt.asm.mov(r8, ptr(0x1480 + r8 * 8).gs()).unwrap();
        // sub r8, ...
        rt.asm.sub(r8, VM_DEBUG_SIZE as i32).unwrap();
        // call r13
        rt.asm.call(r13).unwrap();

        // add rsp, 0x20
        rt.asm.add(rsp, 0x20).unwrap();

        // pop r13
        rt.asm.pop(r13).unwrap();
    }

    // pop r12
    rt.asm.pop(r12).unwrap();
    // ret
    rt.asm.ret().unwrap();
}
