use iced_x86::code_asm::{
    asm_traits::CodeAsmJmp, ptr, r10, r11, rsp, AsmRegister64, CodeAssembler,
};

use crate::runtime::{DataDef, Runtime};

pub const VM_STACK_SIZE: usize = 0x100;

pub fn initialize(rt: &mut Runtime) {
    let mut initialized = rt.asm.create_label();

    // mov r11, [...]
    rt.asm
        .mov(r11, ptr(rt.data_labels[&DataDef::VmStackPointer]))
        .unwrap();
    // test r11, r11
    rt.asm.test(r11, r11).unwrap();
    // jnz ...
    rt.asm.jnz(initialized).unwrap();

    // lea r11, [...]
    rt.asm
        .lea(r11, ptr(rt.data_labels[&DataDef::VmStackContent]))
        .unwrap();
    // add r11, ...
    rt.asm.add(r11, VM_STACK_SIZE as i32).unwrap();
    // mov [...], r11
    rt.asm
        .mov(ptr(rt.data_labels[&DataDef::VmStackPointer]), r11)
        .unwrap();

    rt.asm.set_label(&mut initialized).unwrap();
    {
        // ret
        rt.asm.ret().unwrap();
    }
}

pub fn push(rt: &mut Runtime, src: AsmRegister64) {
    // mov r11, [...]
    rt.asm
        .mov(r11, ptr(rt.data_labels[&DataDef::VmStackPointer]))
        .unwrap();
    // sub r11, 0x8
    rt.asm.sub(r11, 0x8).unwrap();
    // mov [...], r11
    rt.asm
        .mov(ptr(rt.data_labels[&DataDef::VmStackPointer]), r11)
        .unwrap();
    // mov [r11], ...
    rt.asm.mov(ptr(r11), src).unwrap();
}

pub fn pop(rt: &mut Runtime, dst: AsmRegister64) {
    // mov r11, [...]
    rt.asm
        .mov(r11, ptr(rt.data_labels[&DataDef::VmStackPointer]))
        .unwrap();
    // mov ..., [r11]
    rt.asm.mov(dst, ptr(r11)).unwrap();
    // add r11, 0x8
    rt.asm.add(r11, 0x8).unwrap();
    // mov [...], r11
    rt.asm
        .mov(ptr(rt.data_labels[&DataDef::VmStackPointer]), r11)
        .unwrap();
}

// NOTE: Hopefully this does not cause problems :D
pub fn pushfq(rt: &mut Runtime) {
    // mov rsp, ...
    rt.asm
        .mov(rsp, ptr(rt.data_labels[&DataDef::VmStackPointer]))
        .unwrap();
    // pushfq
    rt.asm.pushfq().unwrap();
    // mov [...], rsp
    rt.asm
        .mov(ptr(rt.data_labels[&DataDef::VmStackPointer]), rsp)
        .unwrap();
}

pub fn call<T>(rt: &mut Runtime, target: T)
where
    CodeAssembler: CodeAsmJmp<T>,
{
    let mut ret = rt.asm.create_label();

    // lea r10, [...]
    rt.asm.lea(r10, ptr(ret)).unwrap();
    // push r10
    push(rt, r10);
    // jmp ...
    rt.asm.jmp(target).unwrap();

    rt.asm.set_label(&mut ret).unwrap();
}

pub fn ret(rt: &mut Runtime) {
    // pop r10
    pop(rt, r10);
    // jmp r10
    rt.asm.jmp(r10).unwrap();
}
