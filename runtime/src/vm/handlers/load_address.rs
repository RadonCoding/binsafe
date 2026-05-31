use iced_x86::code_asm::{ptr, r8, r8d, r9, r9d, rax, rcx, rdx};

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{VMReg, VMSeg},
        utils::{self, scratch, stack},
    },
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut add_base = rt.asm.create_label();
    let mut check_index = rt.asm.create_label();
    let mut add_displacement = rt.asm.create_label();
    let mut add_segment = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // xor rax, rax
    rt.asm.xor(rax, rax).unwrap();

    // r8d -> base
    utils::bytecode::read_byte_zx(rt, rdx, r8d);

    // cmp r8, ...
    rt.asm.cmp(r8, rt.mapper.index(VMReg::None) as i32).unwrap();
    // je ...
    rt.asm.je(check_index).unwrap();

    rt.asm.set_label(&mut add_base).unwrap();
    {
        // add rax, [rcx + r8*8]
        rt.asm.add(rax, ptr(rcx + r8 * 8)).unwrap();
    }

    rt.asm.set_label(&mut check_index).unwrap();
    {
        // r8d -> index
        utils::bytecode::read_byte_zx(rt, rdx, r8d);
        // r9d -> scale
        utils::bytecode::read_byte_zx(rt, rdx, r9d);
        // cmp r8, ...
        rt.asm.cmp(r8, rt.mapper.index(VMReg::None) as i32).unwrap();
        // je ...
        rt.asm.je(add_displacement).unwrap();
    }

    // mov r8, [rcx + r8*8]
    rt.asm.mov(r8, ptr(rcx + r8 * 8)).unwrap();
    // imul r8, r9
    rt.asm.imul_2(r8, r9).unwrap();
    // add rax, r8
    rt.asm.add(rax, r8).unwrap();

    rt.asm.set_label(&mut add_displacement).unwrap();
    {
        // r8d -> displacement
        utils::bytecode::read_dword(rt, rdx, r8d);
        // mov r9, [rcx + ...]
        utils::vreg::load_reg(rt, rcx, VMReg::VImm, r9);
        // xor r8d, r9d
        rt.asm.xor(r8d, r9d).unwrap();
        // movsxd r8, r8d
        rt.asm.movsxd(r8, r8d).unwrap();
        // add rax, r8
        rt.asm.add(rax, r8).unwrap();
    }

    // r8d -> segment
    utils::bytecode::read_byte_zx(rt, rdx, r8d);

    // cmp r8, ...
    rt.asm.cmp(r8, rt.mapper.index(VMSeg::None) as i32).unwrap();
    // je ...
    rt.asm.je(epilogue).unwrap();

    rt.asm.set_label(&mut add_segment).unwrap();
    {
        // add rax, gs:[0x30]
        rt.asm.add(rax, ptr(0x30).gs()).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // store rax
        scratch::store(rt, rax);

        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();
        // ret
        stack::ret(rt);
    }
}
