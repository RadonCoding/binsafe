use crate::{runtime::Runtime, vm::bytecode::VMReg};

use iced_x86::code_asm::{ptr, qword_ptr, AsmRegister32, AsmRegister64};

/// `mov {dst}, [{base} + {src} * 8]`
pub fn load_reg(rt: &mut Runtime, base: AsmRegister64, src: VMReg, dst: AsmRegister64) {
    rt.asm
        .mov(dst, ptr(base + rt.mapper.index(src) * 8))
        .unwrap();
}

/// `mov {dst}, [{base} + {src} * 8]`
pub fn load_reg32(rt: &mut Runtime, base: AsmRegister64, src: VMReg, dst: AsmRegister32) {
    rt.asm
        .mov(dst, ptr(base + rt.mapper.index(src) * 8))
        .unwrap();
}

/// `mov {tmp}, [{base} + {src} * 8]`; `mov {dst}, [{tmp}]`
pub fn load_mem(
    rt: &mut Runtime,
    base: AsmRegister64,
    src: VMReg,
    tmp: AsmRegister64,
    dst: AsmRegister64,
) {
    rt.asm
        .mov(tmp, ptr(base + rt.mapper.index(src) * 8))
        .unwrap();
    rt.asm.mov(dst, ptr(tmp)).unwrap();
}

/// `mov [{base} + {dst} * 8], {src}`
pub fn store_reg(rt: &mut Runtime, base: AsmRegister64, src: AsmRegister64, dst: VMReg) {
    rt.asm
        .mov(ptr(base + rt.mapper.index(dst) * 8), src)
        .unwrap();
}

/// `mov [{base} + {dst} * 8], {src}`
pub fn store_reg32(rt: &mut Runtime, base: AsmRegister64, src: AsmRegister32, dst: VMReg) {
    rt.asm
        .mov(ptr(base + rt.mapper.index(dst) * 8), src)
        .unwrap();
}

/// `mov qword [{base} + {dst} * 8], {src}`
pub fn store_imm(rt: &mut Runtime, base: AsmRegister64, src: i32, dst: VMReg) {
    rt.asm
        .mov(qword_ptr(base + rt.mapper.index(dst) * 8), src)
        .unwrap();
}

/// `mov {tmp}, [{base} + {dst} * 8]`; `mov [{tmp}], {src}`
pub fn store_mem(
    rt: &mut Runtime,
    base: AsmRegister64,
    dst: VMReg,
    tmp: AsmRegister64,
    src: AsmRegister64,
) {
    rt.asm
        .mov(tmp, ptr(base + rt.mapper.index(dst) * 8))
        .unwrap();
    rt.asm.mov(ptr(tmp), src).unwrap();
}

/// `add [{base} + {dst} * 8], {src}`
pub fn add_reg(rt: &mut Runtime, base: AsmRegister64, src: AsmRegister64, dst: VMReg) {
    rt.asm
        .add(ptr(base + rt.mapper.index(dst) * 8), src)
        .unwrap();
}

/// `add qword [{base} + {dst} * 8], {src}`
pub fn add_imm(rt: &mut Runtime, base: AsmRegister64, src: i32, dst: VMReg) {
    rt.asm
        .add(qword_ptr(base + rt.mapper.index(dst) * 8), src)
        .unwrap();
}

/// `add {dst}, [{base} + {src} * 8]`
pub fn reg_add(rt: &mut Runtime, base: AsmRegister64, src: VMReg, dst: AsmRegister64) {
    rt.asm
        .add(dst, ptr(base + rt.mapper.index(src) * 8))
        .unwrap();
}

/// `sub [{base} + {dst} * 8], {src}`
pub fn sub_reg(rt: &mut Runtime, base: AsmRegister64, src: AsmRegister64, dst: VMReg) {
    rt.asm
        .sub(ptr(base + rt.mapper.index(dst) * 8), src)
        .unwrap();
}

/// `sub qword [{base} + {dst} * 8], {src}`
pub fn sub_imm(rt: &mut Runtime, base: AsmRegister64, src: i32, dst: VMReg) {
    rt.asm
        .sub(qword_ptr(base + rt.mapper.index(dst) * 8), src)
        .unwrap();
}

/// `sub {dst}, [{base} + {src} * 8]`
pub fn reg_sub(rt: &mut Runtime, base: AsmRegister64, src: VMReg, dst: AsmRegister64) {
    rt.asm
        .sub(dst, ptr(base + rt.mapper.index(src) * 8))
        .unwrap();
}

/// `cmp [{base} + {dst} * 8], {src}`
pub fn cmp_reg(rt: &mut Runtime, base: AsmRegister64, dst: VMReg, src: AsmRegister64) {
    rt.asm
        .cmp(ptr(base + rt.mapper.index(dst) * 8), src)
        .unwrap();
}

/// `cmp qword [{base} + {dst} * 8], {src}`
pub fn cmp_imm(rt: &mut Runtime, base: AsmRegister64, dst: VMReg, src: i32) {
    rt.asm
        .cmp(qword_ptr(base + rt.mapper.index(dst) * 8), src)
        .unwrap();
}

/// `push qword [{base} + {src} * 8]`
pub fn push(rt: &mut Runtime, base: AsmRegister64, src: VMReg) {
    rt.asm
        .push(qword_ptr(base + rt.mapper.index(src) * 8))
        .unwrap();
}

/// `pop qword [{base} + {dst} * 8]`
pub fn pop(rt: &mut Runtime, base: AsmRegister64, dst: VMReg) {
    rt.asm
        .pop(qword_ptr(base + rt.mapper.index(dst) * 8))
        .unwrap();
}
