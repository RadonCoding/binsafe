pub mod compute_address;

use crate::{runtime::Runtime, vm::bytecode::VMReg};
use iced_x86::code_asm::{ptr, qword_ptr, AsmRegister32, AsmRegister64};

pub fn mov_reg_vreg_64(rt: &mut Runtime, src: AsmRegister64, from: VMReg, to: AsmRegister64) {
    // mov ..., [...]
    rt.asm
        .mov(to, ptr(src + rt.mapper.index(from) * 8))
        .unwrap();
}

pub fn mov_reg_vreg_32(rt: &mut Runtime, src: AsmRegister64, from: VMReg, to: AsmRegister32) {
    // mov ..., [...]
    rt.asm
        .mov(to, ptr(src + rt.mapper.index(from) * 8))
        .unwrap();
}

pub fn mov_vreg_reg_64(rt: &mut Runtime, src: AsmRegister64, from: AsmRegister64, to: VMReg) {
    // mov [...], ...
    rt.asm
        .mov(ptr(src + rt.mapper.index(to) * 8), from)
        .unwrap();
}

pub fn add_vreg_reg_64(rt: &mut Runtime, src: AsmRegister64, from: AsmRegister64, to: VMReg) {
    // add [...], ...
    rt.asm
        .add(ptr(src + rt.mapper.index(to) * 8), from)
        .unwrap();
}

pub fn add_vreg_imm_64(rt: &mut Runtime, src: AsmRegister64, from: i32, to: VMReg) {
    // add [...], ...
    rt.asm
        .add(qword_ptr(src + rt.mapper.index(to) * 8), from)
        .unwrap();
}

pub fn add_reg_vreg_64(rt: &mut Runtime, src: AsmRegister64, from: VMReg, to: AsmRegister64) {
    // add ..., [...]
    rt.asm
        .add(to, ptr(src + rt.mapper.index(from) * 8))
        .unwrap();
}

pub fn sub_vreg_reg_64(rt: &mut Runtime, src: AsmRegister64, from: AsmRegister64, to: VMReg) {
    // sub [...], ...
    rt.asm
        .sub(ptr(src + rt.mapper.index(to) * 8), from)
        .unwrap();
}

pub fn sub_vreg_imm_64(rt: &mut Runtime, src: AsmRegister64, from: i32, to: VMReg) {
    // sub [...], ...
    rt.asm
        .sub(qword_ptr(src + rt.mapper.index(to) * 8), from)
        .unwrap();
}

pub fn sub_reg_vreg_64(rt: &mut Runtime, src: AsmRegister64, from: VMReg, to: AsmRegister64) {
    // sub ..., [...]
    rt.asm
        .sub(to, ptr(src + rt.mapper.index(from) * 8))
        .unwrap();
}

pub fn cmp_vreg_reg_64(rt: &mut Runtime, src: AsmRegister64, a: VMReg, b: AsmRegister64) {
    // cmp [...], ...
    rt.asm.cmp(ptr(src + rt.mapper.index(a) * 8), b).unwrap();
}

pub fn store_vreg_mem_64(
    rt: &mut Runtime,
    src: AsmRegister64,
    with: AsmRegister64,
    from: AsmRegister64,
    to: VMReg,
) {
    // mov ..., [...]
    rt.asm
        .mov(with, ptr(src + rt.mapper.index(to) * 8))
        .unwrap();
    // mov [...], ...
    rt.asm.mov(ptr(with), from).unwrap();
}

pub fn load_reg_mem_64(
    rt: &mut Runtime,
    src: AsmRegister64,
    with: AsmRegister64,
    from: VMReg,
    to: AsmRegister64,
) {
    // mov ..., [...]
    rt.asm
        .mov(with, ptr(src + rt.mapper.index(from) * 8))
        .unwrap();
    // mov ..., [...]
    rt.asm.mov(to, ptr(with)).unwrap();
}

pub fn push_vreg_64(rt: &mut Runtime, src: AsmRegister64, from: VMReg) {
    // push [...]
    rt.asm
        .push(qword_ptr(src + rt.mapper.index(from) * 8))
        .unwrap();
}

#[cfg(debug_assertions)]
pub fn print_s(rt: &mut Runtime, s: &str) {
    use std::mem;

    use iced_x86::code_asm::{r8, r9, rax, rcx, rdx, rsp};

    use crate::runtime::FnDef;

    // push rax
    rt.asm.push(rax).unwrap();
    // push rcx
    rt.asm.push(rcx).unwrap();
    // push rdx
    rt.asm.push(rdx).unwrap();
    // push r8
    rt.asm.push(r8).unwrap();
    // push r9
    rt.asm.push(r9).unwrap();

    let mut bytes = s.as_bytes().to_vec();

    bytes.push(0);

    let stack_size = (bytes.len() + 0xF) & !0xF;

    // sub rsp, ...
    rt.asm.sub(rsp, stack_size as i32).unwrap();

    let mut offset = 0;

    for chunk in bytes.chunks(mem::size_of::<u64>()) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);

        let value = u64::from_le_bytes(buf);

        // mov rax, ...
        rt.asm.mov(rax, value).unwrap();
        // mov [rsp + ...], rax
        rt.asm.mov(qword_ptr(rsp + offset), rax).unwrap();

        offset += mem::size_of::<u64>();
    }

    // mov rcx, rsp
    rt.asm.mov(rcx, rsp).unwrap();
    // call ...
    rt.asm.call(rt.func_labels[&FnDef::Print]).unwrap();

    // add rsp, ...
    rt.asm.add(rsp, stack_size as i32).unwrap();

    // pop r9
    rt.asm.pop(r9).unwrap();
    // pop r8
    rt.asm.pop(r8).unwrap();
    // pop rdx
    rt.asm.pop(rdx).unwrap();
    // pop rcx
    rt.asm.pop(rcx).unwrap();
    // pop rax
    rt.asm.pop(rax).unwrap();
}

#[cfg(debug_assertions)]
pub fn print_q(rt: &mut Runtime, reg: AsmRegister64) {
    use iced_x86::code_asm::{r8, r9, rax, rcx, rdx, rsp};

    use crate::runtime::FnDef;

    // push rax
    rt.asm.push(rax).unwrap();
    // push rcx
    rt.asm.push(rcx).unwrap();
    // push rdx
    rt.asm.push(rdx).unwrap();
    // push r8
    rt.asm.push(r8).unwrap();
    // push r9
    rt.asm.push(r9).unwrap();

    // mov rax, ...
    rt.asm.mov(rax, reg).unwrap();

    let stack_size = 0x20;

    // sub rsp, ...
    rt.asm.sub(rsp, stack_size as i32).unwrap();

    // mov rcx, rsp
    rt.asm.mov(rcx, rsp).unwrap();
    // mov rdx, ...
    rt.asm.mov(rdx, rax).unwrap();
    // call ...
    rt.asm.call(rt.func_labels[&FnDef::Fmtdec]).unwrap();

    // mov rcx, rsp
    rt.asm.mov(rcx, rsp).unwrap();
    // call ...
    rt.asm.call(rt.func_labels[&FnDef::Print]).unwrap();

    // add rsp, ...
    rt.asm.add(rsp, stack_size as i32).unwrap();

    // pop r9
    rt.asm.pop(r9).unwrap();
    // pop r8
    rt.asm.pop(r8).unwrap();
    // pop rdx
    rt.asm.pop(rdx).unwrap();
    // pop rcx
    rt.asm.pop(rcx).unwrap();
    // pop rax
    rt.asm.pop(rax).unwrap();
}

#[cfg(debug_assertions)]
fn acquire_global_lock(rt: &mut Runtime) {
    use iced_x86::code_asm::al;

    use crate::runtime::BoolDef;

    let mut wait = rt.asm.create_label();

    rt.asm.set_label(&mut wait).unwrap();
    {
        // mov al, 0x1
        rt.asm.mov(al, 0x1).unwrap();
        // lock xchg [...], al
        rt.asm
            .lock()
            .xchg(ptr(rt.bool_labels[&BoolDef::VmIsLocked]), al)
            .unwrap();
        // test al, al
        rt.asm.test(al, al).unwrap();
        // jnz ...
        rt.asm.jnz(wait).unwrap();
    }
}

#[cfg(debug_assertions)]
fn release_global_lock(rt: &mut Runtime) {
    use iced_x86::code_asm::al;

    use crate::runtime::BoolDef;

    // xor al, al
    rt.asm.xor(al, al).unwrap();
    // lock xchg [...], al
    rt.asm
        .lock()
        .xchg(ptr(rt.bool_labels[&BoolDef::VmIsLocked]), al)
        .unwrap();
}

#[cfg(debug_assertions)]
pub fn start_profiling(rt: &mut Runtime, message: &str) {
    use iced_x86::code_asm::{rax, rdx};

    use crate::vm::{stack, utils};

    // push rdx
    rt.asm.push(rdx).unwrap();
    // push rax
    rt.asm.push(rax).unwrap();

    acquire_global_lock(rt);

    // mov rax, gs:[0x48] -> HANDLE TEB->ClientId->UniqueThread
    rt.asm.mov(rax, ptr(0x48).gs()).unwrap();

    utils::print_s(rt, &format!("Thread "));
    utils::print_q(rt, rax);
    utils::print_s(rt, &format!(" | Starting {}...\n", message));

    // rdtsc
    rt.asm.rdtsc().unwrap();
    // shl rdx, 0x20
    rt.asm.shl(rdx, 0x20).unwrap();
    // or rax, rdx
    rt.asm.or(rax, rdx).unwrap();
    // push rax
    stack::push(rt, rax);

    release_global_lock(rt);

    // pop rax
    rt.asm.pop(rax).unwrap();
    // pop rdx
    rt.asm.pop(rdx).unwrap();
}

#[cfg(debug_assertions)]
pub fn stop_profiling(rt: &mut Runtime, message: &str) {
    use iced_x86::code_asm::{rax, rdx};

    use crate::vm::{stack, utils};

    // push rdx
    rt.asm.push(rdx).unwrap();
    // push rax
    rt.asm.push(rax).unwrap();

    acquire_global_lock(rt);

    // mov rax, gs:[0x48] -> HANDLE TEB->ClientId->UniqueThread
    rt.asm.mov(rax, ptr(0x48).gs()).unwrap();

    utils::print_s(rt, &format!("Thread "));
    utils::print_q(rt, rax);
    utils::print_s(rt, &format!(" | Cycles for {}: ", message));

    // rdtsc
    rt.asm.rdtsc().unwrap();
    // shl rdx, 0x20
    rt.asm.shl(rdx, 0x20).unwrap();
    // or rax, rdx
    rt.asm.or(rax, rdx).unwrap();
    // pop rdx
    stack::pop(rt, rdx);
    // sub rax, rdx
    rt.asm.sub(rax, rdx).unwrap();

    utils::print_q(rt, rax);
    utils::print_s(rt, "\n");

    release_global_lock(rt);

    // pop rax
    rt.asm.pop(rax).unwrap();
    // pop rdx
    rt.asm.pop(rdx).unwrap();
}
