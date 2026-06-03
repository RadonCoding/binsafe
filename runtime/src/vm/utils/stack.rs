use iced_x86::code_asm::{
    asm_traits::CodeAsmJmp, ptr, r10, r11, r11d, rsp, AsmRegister64, CodeAssembler, CodeLabel,
};

use crate::{
    runtime::{DataDef, Runtime},
    vm::{bytecode::VMReg, utils::vreg},
};

pub fn push(rt: &mut Runtime, src: AsmRegister64) {
    // mov r11d, [...]
    rt.asm
        .mov(r11d, ptr(rt.data_labels[&DataDef::VmRegistersTlsIndex]))
        .unwrap();
    // mov r11, gs:[0x1480 + r11*8]
    rt.asm.mov(r11, ptr(0x1480 + r11 * 8).gs()).unwrap();
    // sub [r11 + ...], 0x8
    vreg::sub_imm(rt, r11, 0x8, VMReg::VStack);
    // mov r11, [r11 + ...]
    vreg::load_reg(rt, r11, VMReg::VStack, r11);
    // mov [r11], ...
    rt.asm.mov(ptr(r11), src).unwrap();
}

pub fn pop(rt: &mut Runtime, dst: AsmRegister64) {
    // mov r11d, [...]
    rt.asm
        .mov(r11d, ptr(rt.data_labels[&DataDef::VmRegistersTlsIndex]))
        .unwrap();
    // mov r11, gs:[0x1480 + r11*8]
    rt.asm.mov(r11, ptr(0x1480 + r11 * 8).gs()).unwrap();
    // add [r11 + ...], 0x8
    vreg::add_imm(rt, r11, 0x8, VMReg::VStack);
    // mov r11, [r11 + ...]
    vreg::load_reg(rt, r11, VMReg::VStack, r11);
    // mov ..., [r11 - 0x8]
    rt.asm.mov(dst, ptr(r11 - 0x8)).unwrap();
}

pub fn with_stack_pivot<F>(rt: &mut Runtime, f: F)
where
    F: FnOnce(&mut Runtime),
{
    // mov r10, rsp
    rt.asm.mov(r10, rsp).unwrap();

    // mov r11d, [...]
    rt.asm
        .mov(r11d, ptr(rt.data_labels[&DataDef::VmRegistersTlsIndex]))
        .unwrap();
    // mov r11, gs:[0x1480 + r11*8]
    rt.asm.mov(r11, ptr(0x1480 + r11 * 8).gs()).unwrap();
    // mov rsp, [r11 + ...]
    vreg::load_reg(rt, r11, VMReg::VStack, rsp);

    f(rt);

    // mov r11d, [...]
    rt.asm
        .mov(r11d, ptr(rt.data_labels[&DataDef::VmRegistersTlsIndex]))
        .unwrap();
    // mov r11, gs:[0x1480 + r11*8]
    rt.asm.mov(r11, ptr(0x1480 + r11 * 8).gs()).unwrap();
    // mov [r11 + ...], rsp
    vreg::store_reg(rt, r11, rsp, VMReg::VStack);

    // mov rsp, r10
    rt.asm.mov(rsp, r10).unwrap();
}

pub fn pushfq(rt: &mut Runtime) {
    with_stack_pivot(rt, |rt| {
        // pushfq
        rt.asm.pushfq().unwrap();
    });
}

pub fn call<T>(rt: &mut Runtime, target: T)
where
    CodeAssembler: CodeAsmJmp<T>,
{
    let mut ret = rt.asm.create_label();
    call_with_label(rt, target, &mut ret);
    rt.asm.set_label(&mut ret).unwrap();
    rt.asm.zero_bytes().unwrap();
}

pub fn call_with_label<T>(rt: &mut Runtime, target: T, ret: &CodeLabel)
where
    CodeAssembler: CodeAsmJmp<T>,
{
    // lea r10, [...]
    rt.asm.lea(r10, ptr(*ret)).unwrap();
    // push r10
    push(rt, r10);
    // jmp ...
    rt.asm.jmp(target).unwrap();
}

pub fn ret(rt: &mut Runtime) {
    // pop r10
    pop(rt, r10);
    // jmp r10
    rt.asm.jmp(r10).unwrap();
}
