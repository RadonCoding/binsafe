use iced_x86::code_asm::{byte_ptr, dword_ptr, eax, ptr, r8b, r8d, r9b, rax, rcx, rdx};

use crate::{
    runtime::Runtime,
    vm::{bytecode::VMReg, utils},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut equal = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // movzx eax, [rdx] -> flag
    rt.asm.movzx(eax, byte_ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // mov r8d, [rcx + ...]
    utils::mov_reg_vreg_32(rt, rcx, VMReg::Flags, r8d);

    // bt r8d, eax
    rt.asm.bt(r8d, eax).unwrap();
    // setc r8b
    rt.asm.setc(r8b).unwrap();

    // mov r9b, [rdx] -> set
    rt.asm.mov(r9b, ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // movsxd rax, [rdx] -> dst
    rt.asm.movsxd(rax, dword_ptr(rdx)).unwrap();
    // add rdx, 0x4
    rt.asm.add(rdx, 0x4).unwrap();

    // cmp r8b, r9b
    rt.asm.cmp(r8b, r9b).unwrap();

    // jne ...
    rt.asm.jne(epilogue).unwrap();

    rt.asm.set_label(&mut equal).unwrap();
    {
        // add [rcx + ...], rax
        utils::add_vreg_reg_64(rt, rcx, rax, VMReg::Rip);
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
