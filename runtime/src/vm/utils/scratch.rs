use iced_x86::code_asm::{ptr, qword_ptr, r11, r11d, AsmRegister64};

use crate::runtime::{DataDef, Runtime};

pub fn store(rt: &mut Runtime, src: AsmRegister64) {
    // mov r11d, [...]
    rt.asm
        .mov(r11d, ptr(rt.data_labels[&DataDef::VmScratchTlsIndex]))
        .unwrap();
    // sub gs:[0x1480 + r11*8], 0x8
    rt.asm.sub(qword_ptr(0x1480 + r11 * 8).gs(), 0x8).unwrap();
    // mov r11, gs:[0x1480 + r11*8]
    rt.asm.mov(r11, ptr(0x1480 + r11 * 8).gs()).unwrap();
    // mov [r11], ...
    rt.asm.mov(ptr(r11), src).unwrap();
}

pub fn load(rt: &mut Runtime, dst: AsmRegister64) {
    // mov r11d, [...]
    rt.asm
        .mov(r11d, ptr(rt.data_labels[&DataDef::VmScratchTlsIndex]))
        .unwrap();
    // add gs:[0x1480 + r11*8], 0x8
    rt.asm.add(qword_ptr(0x1480 + r11 * 8).gs(), 0x8).unwrap();
    // mov r11, gs:[0x1480 + r11*8]
    rt.asm.mov(r11, ptr(0x1480 + r11 * 8).gs()).unwrap();
    // mov ..., [r11 - 0x8]
    rt.asm.mov(dst, ptr(r11 - 0x8)).unwrap();
}

pub fn peek(rt: &mut Runtime, dst: AsmRegister64) {
    // mov r11d, [...]
    rt.asm
        .mov(r11d, ptr(rt.data_labels[&DataDef::VmScratchTlsIndex]))
        .unwrap();
    // mov r11, gs:[0x1480 + r11*8]
    rt.asm.mov(r11, ptr(0x1480 + r11 * 8).gs()).unwrap();
    // mov ..., [r11]
    rt.asm.mov(dst, ptr(r11)).unwrap();
}
