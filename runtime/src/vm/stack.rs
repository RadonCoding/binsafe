use iced_x86::code_asm::{
    asm_traits::CodeAsmJmp, ptr, qword_ptr, r10, r11, r11d, rsp, AsmRegister64, CodeAssembler,
    CodeLabel,
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

// pub fn with_stack_pivot<F>(rt: &mut Runtime, f: F)
// where
//     F: FnOnce(&mut Runtime),
// {
//     // mov r10, rsp
//     rt.asm.mov(r10, rsp).unwrap();

//     // mov r11d, [...]
//     rt.asm
//         .mov(r11d, ptr(rt.data_labels[&DataDef::VmStackTlsIndex]))
//         .unwrap();
//     // mov r11, gs:[0x1480 + r11*8]
//     rt.asm.mov(r11, ptr(0x1480 + r11 * 8).gs()).unwrap();

//     // mov rsp, r11
//     rt.asm.mov(rsp, r11).unwrap();

//     f(rt);

//     // mov r11d, [...]
//     rt.asm
//         .mov(r11d, ptr(rt.data_labels[&DataDef::VmStackTlsIndex]))
//         .unwrap();
//     // mov gs:[0x1480 + r11*8], rsp
//     rt.asm.mov(qword_ptr(0x1480 + r11 * 8).gs(), rsp).unwrap();

//     // mov rsp, r10
//     rt.asm.mov(rsp, r10).unwrap();
// }

// pub fn pushfq(rt: &mut Runtime) {
//     with_stack_pivot(rt, |rt| {
//         // pushfq
//         rt.asm.pushfq().unwrap();
//     });
// }

pub fn call<T>(rt: &mut Runtime, target: T)
where
    CodeAssembler: CodeAsmJmp<T>,
{
    let mut ret = rt.asm.create_label();
    call_with_label(rt, target, &mut ret);
    rt.asm.set_label(&mut ret).unwrap();
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
