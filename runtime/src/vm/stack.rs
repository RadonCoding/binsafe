use iced_x86::code_asm::{
    al, asm_traits::CodeAsmJmp, ptr, r10, r11, r11b, rax, AsmRegister64, CodeAssembler, CodeLabel,
};

use crate::runtime::{DataDef, Runtime};

pub const VSTACK_SIZE: usize = 0x100;

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
    rt.asm.add(r11, VSTACK_SIZE as i32).unwrap();
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
    // mov r10, rax
    rt.asm.mov(r10, rax).unwrap();

    // lahf
    rt.asm.lahf().unwrap();
    // seto r11b
    rt.asm.seto(r11b).unwrap();

    // movzx r11, r11b
    rt.asm.movzx(r11, r11b).unwrap();
    // shl r11, 0xb
    rt.asm.shl(r11, 0xb).unwrap();

    // shr rax, 0x8
    rt.asm.shr(rax, 0x8).unwrap();
    // movzx rax, al
    rt.asm.movzx(rax, al).unwrap();
    // or r11, rax
    rt.asm.or(r11, rax).unwrap();

    // mov rax, r10
    rt.asm.mov(rax, r10).unwrap();

    // mov r10, [...]
    rt.asm
        .mov(r10, ptr(rt.data_labels[&DataDef::VmStackPointer]))
        .unwrap();
    // sub r10, 0x8
    rt.asm.sub(r10, 0x8).unwrap();
    // mov [r10], r11
    rt.asm.mov(ptr(r10), r11).unwrap();
    // mov [...], r10
    rt.asm
        .mov(ptr(rt.data_labels[&DataDef::VmStackPointer]), r10)
        .unwrap();
}

pub fn call<T>(rt: &mut Runtime, target: T)
where
    CodeAssembler: CodeAsmJmp<T>,
{
    let mut ret = rt.asm.create_label();
    call_with_label(rt, target, &mut ret);
    rt.asm.set_label(&mut ret).unwrap();
}

pub fn call_with_label<T>(rt: &mut Runtime, target: T, ret: &mut CodeLabel)
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
