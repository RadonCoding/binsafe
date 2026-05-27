use crate::runtime::Runtime;
use iced_x86::code_asm::{
    byte_ptr, ptr, AsmRegister16, AsmRegister32, AsmRegister64, AsmRegister8,
};

/// `mov {to}, [{base}]`; `add {base}, 0x1`
pub fn read_byte(rt: &mut Runtime, base: AsmRegister64, to: AsmRegister8) {
    // mov ..., [...]
    rt.asm.mov(to, ptr(base)).unwrap();
    // add ..., 0x1
    rt.asm.add(base, 0x1).unwrap();
}

/// `movzx {to}, [{base}]`; `add {base}, 0x1`
pub fn read_byte_zx(rt: &mut Runtime, base: AsmRegister64, to: AsmRegister64) {
    // movzx ..., [...]
    rt.asm.movzx(to, byte_ptr(base)).unwrap();
    // add ..., 0x1
    rt.asm.add(base, 0x1).unwrap();
}

/// `mov {to}, [{base}]`; `add {base}, 0x2`
pub fn read_word(rt: &mut Runtime, base: AsmRegister64, to: AsmRegister16) {
    // mov ..., [...]
    rt.asm.mov(to, ptr(base)).unwrap();
    // add ..., 0x2
    rt.asm.add(base, 0x2).unwrap();
}

/// `mov {to}, [{base}]`; `add {base}, 0x4`
pub fn read_dword(rt: &mut Runtime, base: AsmRegister64, to: AsmRegister32) {
    // mov ..., [...]
    rt.asm.mov(to, ptr(base)).unwrap();
    // add ..., 0x4
    rt.asm.add(base, 0x4).unwrap();
}

/// `mov {to}, [{base}]`; `add {base}, 0x8`
pub fn read_qword(rt: &mut Runtime, base: AsmRegister64, to: AsmRegister64) {
    // mov ..., [...]
    rt.asm.mov(to, ptr(base)).unwrap();
    // add ..., 0x8
    rt.asm.add(base, 0x8).unwrap();
}
