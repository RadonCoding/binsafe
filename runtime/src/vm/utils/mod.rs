pub mod compute_address;

use crate::{runtime::Runtime, vm::bytecode::VMReg};

use iced_x86::code_asm::{ptr, qword_ptr, AsmRegister32, AsmRegister64, AsmRegister8, CodeLabel};

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

pub fn mov_vreg_imm_64(rt: &mut Runtime, src: AsmRegister64, from: i32, to: VMReg) {
    // mov [...], ...
    rt.asm
        .mov(qword_ptr(src + rt.mapper.index(to) * 8), from)
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

pub fn cmp_vreg_imm_64(rt: &mut Runtime, src: AsmRegister64, a: VMReg, b: i32) {
    // cmp [...], ...
    rt.asm
        .cmp(qword_ptr(src + rt.mapper.index(a) * 8), b)
        .unwrap();
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

pub fn acquire_global_lock(rt: &mut Runtime, scratch: AsmRegister8, label: Option<&mut CodeLabel>) {
    use crate::runtime::BoolDef;
    use iced_x86::code_asm::{byte_ptr, ptr};

    let spin = if let Some(label) = label {
        label
    } else {
        &mut rt.asm.create_label()
    };
    let mut acquire = rt.asm.create_label();

    rt.asm.set_label(spin).unwrap();
    {
        // cmp byte [...], 0x0
        rt.asm
            .cmp(byte_ptr(rt.bool_labels[&BoolDef::VmIsLocked]), 0x0)
            .unwrap();
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
        rt.asm
            .xchg(ptr(rt.bool_labels[&BoolDef::VmIsLocked]), scratch)
            .unwrap();
        // test ..., ...
        rt.asm.test(scratch, scratch).unwrap();
        // jnz ...
        rt.asm.jnz(*spin).unwrap();
    }
}

pub fn release_global_lock(rt: &mut Runtime) {
    use iced_x86::code_asm::byte_ptr;

    use crate::runtime::BoolDef;

    // mov [...], 0x0
    rt.asm
        .mov(byte_ptr(rt.bool_labels[&BoolDef::VmIsLocked]), 0x0)
        .unwrap();
}

#[cfg(debug_assertions)]
pub fn with_stack_pivot<F>(rt: &mut Runtime, src: AsmRegister64, f: F)
where
    F: FnOnce(&mut Runtime),
{
    use iced_x86::code_asm::{rax, rsp};

    use crate::vm::stack;

    // push rsp
    stack::push(rt, rsp);
    // mov rsp, [...]
    rt.asm
        .mov(rsp, ptr(src + rt.mapper.index(VMReg::Rsp) * 8))
        .unwrap();
    // push rax
    rt.asm.push(rax).unwrap();
    // pop rax
    stack::pop(rt, rax);

    f(rt);

    // pop rsp
    rt.asm.pop(rsp).unwrap();
}

#[cfg(debug_assertions)]
fn print_thread_prefix(rt: &mut Runtime) {
    use crate::vm::utils;
    use iced_x86::code_asm::rax;

    // push rax
    rt.asm.push(rax).unwrap();

    // mov rax, gs:[0x48] -> HANDLE TEB->ClientId->UniqueThread
    rt.asm.mov(rax, ptr(0x48).gs()).unwrap();

    utils::print_s(rt, "Thread ");
    utils::print_q(rt, rax);
    utils::print_s(rt, " | ");

    // pop rax
    rt.asm.pop(rax).unwrap();
}

#[cfg(debug_assertions)]
pub fn start_profiling(rt: &mut Runtime, message: &str) {
    use iced_x86::code_asm::{al, rax, rdx};

    use crate::vm::stack;

    // push rax
    rt.asm.push(rax).unwrap();
    // push rdx
    rt.asm.push(rdx).unwrap();

    acquire_global_lock(rt, al, None);
    print_thread_prefix(rt);
    print_s(rt, &format!("Starting {}...\n", message));
    release_global_lock(rt);

    // rdtsc
    rt.asm.rdtsc().unwrap();
    // shl rdx, 0x20
    rt.asm.shl(rdx, 0x20).unwrap();
    // or rax, rdx
    rt.asm.or(rax, rdx).unwrap();
    // push rax
    stack::push(rt, rax);

    // pop rdx
    rt.asm.pop(rdx).unwrap();
    // pop rax
    rt.asm.pop(rax).unwrap();
}

#[cfg(debug_assertions)]
pub fn stop_profiling(rt: &mut Runtime, message: &str) {
    use iced_x86::code_asm::{al, rax, rdx};

    use crate::vm::stack;

    // push rdx
    rt.asm.push(rdx).unwrap();
    // push rax
    rt.asm.push(rax).unwrap();

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

    acquire_global_lock(rt, al, None);
    print_thread_prefix(rt);
    print_s(rt, &format!("Cycles for {}: ", message));
    print_q(rt, rax);
    print_s(rt, "\n");
    release_global_lock(rt);

    // pop rax
    rt.asm.pop(rax).unwrap();
    // pop rdx
    rt.asm.pop(rdx).unwrap();
}
