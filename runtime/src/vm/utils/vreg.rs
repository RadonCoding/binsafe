use crate::{runtime::Runtime, vm::bytecode::VMReg};
use iced_x86::code_asm::{ptr, qword_ptr, AsmRegister32, AsmRegister64};

/// `mov {to}, [{base} + {from} * 8]`
pub fn load_reg(rt: &mut Runtime, base: AsmRegister64, from: VMReg, to: AsmRegister64) {
    // mov ..., [...]
    rt.asm
        .mov(to, ptr(base + rt.mapper.index(from) * 8))
        .unwrap();
}

/// `mov {to}, [{base} + {from} * 8]`
pub fn load_reg32(rt: &mut Runtime, base: AsmRegister64, from: VMReg, to: AsmRegister32) {
    // mov ..., [...]
    rt.asm
        .mov(to, ptr(base + rt.mapper.index(from) * 8))
        .unwrap();
}

/// `mov {tmp}, [{base} + {from} * 8]`; `mov {to}, [{tmp}]`
pub fn load_mem(
    rt: &mut Runtime,
    base: AsmRegister64,
    tmp: AsmRegister64,
    from: VMReg,
    to: AsmRegister64,
) {
    // mov ..., [...]
    rt.asm
        .mov(tmp, ptr(base + rt.mapper.index(from) * 8))
        .unwrap();
    // mov ..., [...]
    rt.asm.mov(to, ptr(tmp)).unwrap();
}

/// `mov [{base} + {to} * 8], {from}`
pub fn store_reg(rt: &mut Runtime, base: AsmRegister64, from: AsmRegister64, to: VMReg) {
    // mov [...], ...
    rt.asm
        .mov(ptr(base + rt.mapper.index(to) * 8), from)
        .unwrap();
}

/// `mov qword [{base} + {to} * 8], {from}`
pub fn store_imm(rt: &mut Runtime, base: AsmRegister64, from: i32, to: VMReg) {
    // mov [...], ...
    rt.asm
        .mov(qword_ptr(base + rt.mapper.index(to) * 8), from)
        .unwrap();
}

/// `mov {tmp}, [{base} + {to} * 8]`; `mov [{tmp}], {from}`
pub fn store_mem(
    rt: &mut Runtime,
    base: AsmRegister64,
    tmp: AsmRegister64,
    from: AsmRegister64,
    to: VMReg,
) {
    // mov ..., [...]
    rt.asm
        .mov(tmp, ptr(base + rt.mapper.index(to) * 8))
        .unwrap();
    // mov [...], ...
    rt.asm.mov(ptr(tmp), from).unwrap();
}

/// `add [{base} + {to} * 8], {from}`
pub fn add_reg(rt: &mut Runtime, base: AsmRegister64, from: AsmRegister64, to: VMReg) {
    // add [...], ...
    rt.asm
        .add(ptr(base + rt.mapper.index(to) * 8), from)
        .unwrap();
}

/// `add qword [{base} + {to} * 8], {from}`
pub fn add_imm(rt: &mut Runtime, base: AsmRegister64, from: i32, to: VMReg) {
    // add [...], ...
    rt.asm
        .add(qword_ptr(base + rt.mapper.index(to) * 8), from)
        .unwrap();
}

/// `add {to}, [{base} + {from} * 8]`
pub fn reg_add(rt: &mut Runtime, base: AsmRegister64, from: VMReg, to: AsmRegister64) {
    // add ..., [...]
    rt.asm
        .add(to, ptr(base + rt.mapper.index(from) * 8))
        .unwrap();
}

/// `sub [{base} + {to} * 8], {from}`
pub fn sub_reg(rt: &mut Runtime, base: AsmRegister64, from: AsmRegister64, to: VMReg) {
    // sub [...], ...
    rt.asm
        .sub(ptr(base + rt.mapper.index(to) * 8), from)
        .unwrap();
}

/// `sub qword [{base} + {to} * 8], {from}`
pub fn sub_imm(rt: &mut Runtime, base: AsmRegister64, from: i32, to: VMReg) {
    // sub [...], ...
    rt.asm
        .sub(qword_ptr(base + rt.mapper.index(to) * 8), from)
        .unwrap();
}

/// `sub {to}, [{base} + {from} * 8]`
pub fn reg_sub(rt: &mut Runtime, base: AsmRegister64, from: VMReg, to: AsmRegister64) {
    // sub ..., [...]
    rt.asm
        .sub(to, ptr(base + rt.mapper.index(from) * 8))
        .unwrap();
}

/// `cmp [{base} + {a} * 8], {b}`
pub fn cmp_reg(rt: &mut Runtime, base: AsmRegister64, a: VMReg, b: AsmRegister64) {
    // cmp [...], ...
    rt.asm.cmp(ptr(base + rt.mapper.index(a) * 8), b).unwrap();
}

/// `cmp qword [{base} + {a} * 8], {b}`
pub fn cmp_imm(rt: &mut Runtime, base: AsmRegister64, a: VMReg, b: i32) {
    // cmp [...], ...
    rt.asm
        .cmp(qword_ptr(base + rt.mapper.index(a) * 8), b)
        .unwrap();
}

/// `push qword [{base} + {from} * 8]`
pub fn push(rt: &mut Runtime, base: AsmRegister64, from: VMReg) {
    // push [...]
    rt.asm
        .push(qword_ptr(base + rt.mapper.index(from) * 8))
        .unwrap();
}
