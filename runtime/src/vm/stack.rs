use iced_x86::code_asm::{
    al, asm_traits::CodeAsmJmp, ptr, qword_ptr, r10, r10d, r11, r11b, r11d, rax, AsmRegister64,
    CodeAssembler, CodeLabel,
};

use crate::runtime::{DataDef, Runtime};

pub fn push(rt: &mut Runtime, src: AsmRegister64) {
    // mov r11d, [...]
    rt.asm
        .mov(r11d, ptr(rt.data_labels[&DataDef::VmStackTlsIndex]))
        .unwrap();
    // sub gs:[0x1480 + r11*8], 0x8
    rt.asm.sub(qword_ptr(0x1480 + r11 * 8).gs(), 0x8).unwrap();
    // mov r11, gs:[0x1480 + r11*8]
    rt.asm.mov(r11, ptr(0x1480 + r11 * 8).gs()).unwrap();
    // mov [r11], ...
    rt.asm.mov(ptr(r11), src).unwrap();
}

pub fn pop(rt: &mut Runtime, dst: AsmRegister64) {
    // mov r11d, [...]
    rt.asm
        .mov(r11d, ptr(rt.data_labels[&DataDef::VmStackTlsIndex]))
        .unwrap();
    // add gs:[0x1480 + r11*8], 0x8
    rt.asm.add(qword_ptr(0x1480 + r11 * 8).gs(), 0x8).unwrap();
    // mov r11, gs:[0x1480 + r11*8]
    rt.asm.mov(r11, ptr(0x1480 + r11 * 8).gs()).unwrap();
    // mov ..., [r11 - 0x8]
    rt.asm.mov(dst, ptr(r11 - 0x8)).unwrap();
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

    // mov r10d, [...]
    rt.asm
        .mov(r10d, ptr(rt.data_labels[&DataDef::VmStackTlsIndex]))
        .unwrap();
    // sub gs:[0x1480 + r10*8], 0x8
    rt.asm.sub(qword_ptr(0x1480 + r10 * 8).gs(), 0x8).unwrap();
    // mov r10, gs:[0x1480 + r10*8]
    rt.asm.mov(r10, ptr(0x1480 + r10 * 8).gs()).unwrap();
    // mov [r10], r11
    rt.asm.mov(ptr(r10), r11).unwrap();
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
