use crate::{runtime::Runtime, vm::bytecode::VMReg};
use iced_x86::code_asm::{ptr, qword_ptr, AsmMemoryOperand, AsmRegister32, AsmRegister64};

/// `mov {dst}, [{base} + {reg} * 8]`
pub fn load_reg<B: Into<AsmMemoryOperand>>(
    rt: &mut Runtime,
    base: B,
    reg: VMReg,
    dst: AsmRegister64,
) {
    rt.asm
        .mov(dst, base.into() + rt.mapper.index(reg) * 8)
        .unwrap();
}

/// `mov {dst}, [{base} + {reg} * 8]`
pub fn load_reg32<B: Into<AsmMemoryOperand>>(
    rt: &mut Runtime,
    base: B,
    reg: VMReg,
    dst: AsmRegister32,
) {
    rt.asm
        .mov(dst, base.into() + rt.mapper.index(reg) * 8)
        .unwrap();
}

/// `mov {tmp}, [{base} + {reg} * 8]`; `mov {dst}, [{tmp}]`
pub fn load_mem(
    rt: &mut Runtime,
    base: AsmRegister64,
    reg: VMReg,
    tmp: AsmRegister64,
    dst: AsmRegister64,
) {
    rt.asm
        .mov(tmp, ptr(base + rt.mapper.index(reg) * 8))
        .unwrap();
    rt.asm.mov(dst, ptr(tmp)).unwrap();
}

/// `mov [{base} + {reg} * 8], {src}`
pub fn store_reg<B: Into<AsmMemoryOperand>>(
    rt: &mut Runtime,
    base: B,
    src: AsmRegister64,
    reg: VMReg,
) {
    rt.asm
        .mov(base.into() + rt.mapper.index(reg) * 8, src)
        .unwrap();
}

/// `mov [{base} + {reg} * 8], {src}`
pub fn store_reg32<B: Into<AsmMemoryOperand>>(
    rt: &mut Runtime,
    base: B,
    src: AsmRegister32,
    reg: VMReg,
) {
    rt.asm
        .mov(base.into() + rt.mapper.index(reg) * 8, src)
        .unwrap();
}

/// `mov qword [{base} + {reg} * 8], {src}`
pub fn store_imm<B: Into<AsmMemoryOperand>>(rt: &mut Runtime, base: B, src: i32, reg: VMReg) {
    rt.asm
        .mov(qword_ptr(base.into() + rt.mapper.index(reg) * 8), src)
        .unwrap();
}

/// `mov {tmp}, [{base} + {reg} * 8]`; `mov [{tmp}], {src}`
pub fn store_mem(
    rt: &mut Runtime,
    base: AsmRegister64,
    reg: VMReg,
    tmp: AsmRegister64,
    src: AsmRegister64,
) {
    rt.asm
        .mov(tmp, ptr(base + rt.mapper.index(reg) * 8))
        .unwrap();
    rt.asm.mov(ptr(tmp), src).unwrap();
}

/// `add [{base} + {reg} * 8], {src}`
pub fn add_reg<B: Into<AsmMemoryOperand>>(
    rt: &mut Runtime,
    base: B,
    src: AsmRegister64,
    reg: VMReg,
) {
    rt.asm
        .add(base.into() + rt.mapper.index(reg) * 8, src)
        .unwrap();
}

/// `add qword [{base} + {reg} * 8], {src}`
pub fn add_imm<B: Into<AsmMemoryOperand>>(rt: &mut Runtime, base: B, src: i32, reg: VMReg) {
    rt.asm
        .add(qword_ptr(base.into() + rt.mapper.index(reg) * 8), src)
        .unwrap();
}

/// `add {dst}, [{base} + {reg} * 8]`
pub fn reg_add<B: Into<AsmMemoryOperand>>(
    rt: &mut Runtime,
    base: B,
    reg: VMReg,
    dst: AsmRegister64,
) {
    rt.asm
        .add(dst, base.into() + rt.mapper.index(reg) * 8)
        .unwrap();
}

/// `sub [{base} + {reg} * 8], {src}`
pub fn sub_reg<B: Into<AsmMemoryOperand>>(
    rt: &mut Runtime,
    base: B,
    src: AsmRegister64,
    reg: VMReg,
) {
    rt.asm
        .sub(base.into() + rt.mapper.index(reg) * 8, src)
        .unwrap();
}

/// `sub qword [{base} + {reg} * 8], {src}`
pub fn sub_imm<B: Into<AsmMemoryOperand>>(rt: &mut Runtime, base: B, src: i32, reg: VMReg) {
    rt.asm
        .sub(qword_ptr(base.into() + rt.mapper.index(reg) * 8), src)
        .unwrap();
}

/// `sub {dst}, [{base} + {reg} * 8]`
pub fn reg_sub<B: Into<AsmMemoryOperand>>(
    rt: &mut Runtime,
    base: B,
    reg: VMReg,
    dst: AsmRegister64,
) {
    rt.asm
        .sub(dst, base.into() + rt.mapper.index(reg) * 8)
        .unwrap();
}

/// `cmp [{base} + {reg} * 8], {src}`
pub fn cmp_reg<B: Into<AsmMemoryOperand>>(
    rt: &mut Runtime,
    base: B,
    reg: VMReg,
    src: AsmRegister64,
) {
    rt.asm
        .cmp(base.into() + rt.mapper.index(reg) * 8, src)
        .unwrap();
}

/// `cmp qword [{base} + {reg} * 8], {src}`
pub fn cmp_imm<B: Into<AsmMemoryOperand>>(rt: &mut Runtime, base: B, reg: VMReg, src: i32) {
    rt.asm
        .cmp(qword_ptr(base.into() + rt.mapper.index(reg) * 8), src)
        .unwrap();
}

/// `push qword [{base} + {reg} * 8]`
pub fn push<B: Into<AsmMemoryOperand>>(rt: &mut Runtime, base: B, reg: VMReg) {
    rt.asm
        .push(qword_ptr(base.into() + rt.mapper.index(reg) * 8))
        .unwrap();
}

/// `pop qword [{base} + {reg} * 8]`
pub fn pop<B: Into<AsmMemoryOperand>>(rt: &mut Runtime, base: B, reg: VMReg) {
    rt.asm
        .pop(qword_ptr(base.into() + rt.mapper.index(reg) * 8))
        .unwrap();
}
