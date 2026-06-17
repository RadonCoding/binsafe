use crate::runtime::{BoolDef, Runtime};
use iced_x86::code_asm::{byte_ptr, ptr, AsmRegister8, CodeLabel};

fn acquire(rt: &mut Runtime, scratch: AsmRegister8, label: Option<&mut CodeLabel>, def: BoolDef) {
    let spin = if let Some(label) = label {
        label
    } else {
        &mut rt.asm.create_label()
    };
    let mut acquire = rt.asm.create_label();

    rt.asm.set_label(spin).unwrap();
    {
        // cmp byte [...], 0x0
        rt.asm.cmp(byte_ptr(rt.bool_labels[&def]), 0x0).unwrap();
        // pause
        rt.asm.pause().unwrap();
        // jne ...
        rt.asm.jne(*spin).unwrap();
    }

    rt.asm.set_label(&mut acquire).unwrap();
    {
        // mov ..., 0x1
        rt.asm.mov(scratch, 0x1).unwrap();
        // xchg [...], ...
        rt.asm.xchg(ptr(rt.bool_labels[&def]), scratch).unwrap();
        // test ..., ...
        rt.asm.test(scratch, scratch).unwrap();
        // jnz ...
        rt.asm.jnz(*spin).unwrap();
    }
}

fn release(rt: &mut Runtime, def: BoolDef) {
    // mov [...], 0x0
    rt.asm.mov(byte_ptr(rt.bool_labels[&def]), 0x0).unwrap();
}

pub fn acquire_global(rt: &mut Runtime, scratch: AsmRegister8, label: Option<&mut CodeLabel>) {
    acquire(rt, scratch, label, BoolDef::VmIsLocked);
}

pub fn release_global(rt: &mut Runtime) {
    release(rt, BoolDef::VmIsLocked);
}

#[cfg(debug_assertions)]
pub fn acquire_debug(rt: &mut Runtime, scratch: AsmRegister8, label: Option<&mut CodeLabel>) {
    acquire(rt, scratch, label, BoolDef::VmDebug);
}

#[cfg(debug_assertions)]
pub fn release_debug(rt: &mut Runtime) {
    release(rt, BoolDef::VmDebug);
}
