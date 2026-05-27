use iced_x86::code_asm::{ptr, r8, r8d, r9, r9d, rax, rcx, rdx};

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{VMReg, VMSeg},
        stack, utils,
    },
};

// unsigned long, unsigned long (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut add_base = rt.asm.create_label();
    let mut check_index = rt.asm.create_label();
    let mut add_displacement = rt.asm.create_label();
    let mut add_seg = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // xor rax, rax
    rt.asm.xor(rax, rax).unwrap();

    // movzx r8, [rdx]; add rdx, 0x1 -> base
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
        // movzx r8, [rdx]; add rdx, 0x1 -> index
        utils::bytecode::read_byte_zx(rt, rdx, r8d);
        // movzx r9, [rdx]; add rdx, 0x1 -> scale
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
        // movsxd r8, [rdx]; add rdx, 0x4 -> displacement
        utils::bytecode::read_dword_sx(rt, rdx, r8);

        // add rax, r8
        rt.asm.add(rax, r8).unwrap();
    }

    // movzx r8, [rdx]; add rdx, 0x1 -> seg
    utils::bytecode::read_byte_zx(rt, rdx, r8d);

    // cmp r8, ...
    rt.asm.cmp(r8, rt.mapper.index(VMSeg::None) as i32).unwrap();
    // je ...
    rt.asm.je(epilogue).unwrap();

    rt.asm.set_label(&mut add_seg).unwrap();
    {
        // add rax, gs:[0x30] -> NT_TIB *TEB->NT_TIB.Self
        rt.asm.add(rax, ptr(0x30).gs()).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // ret
        stack::ret(rt);
    }
}
