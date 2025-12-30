use iced_x86::code_asm::{byte_ptr, dword_ptr, ptr, r8, r9, rax, rcx, rdx};

use crate::{runtime::Runtime, vm::stack};

// unsigned long, unsigned long (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut add_base = rt.asm.create_label();
    let mut check_index = rt.asm.create_label();
    let mut add_displ = rt.asm.create_label();
    let mut add_seg = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // xor rax, rax
    rt.asm.xor(rax, rax).unwrap();

    // movzx r8, [rdx] -> base
    rt.asm.movzx(r8, byte_ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // test r8, r8
    rt.asm.test(r8, r8).unwrap();
    // jz ...
    rt.asm.jz(check_index).unwrap();

    rt.asm.set_label(&mut add_base).unwrap();
    {
        // dec r8
        rt.asm.dec(r8).unwrap();
        // add rax, [rcx + r8*8]
        rt.asm.add(rax, ptr(rcx + r8 * 8)).unwrap();
    }

    rt.asm.set_label(&mut check_index).unwrap();
    {
        // movzx r8, [rdx] -> index
        rt.asm.movzx(r8, byte_ptr(rdx)).unwrap();
        // add rdx, 0x1
        rt.asm.add(rdx, 0x1).unwrap();

        // movzx r9, [rdx] -> scale
        rt.asm.movzx(r9, byte_ptr(rdx)).unwrap();
        // add rdx, 0x1
        rt.asm.add(rdx, 0x1).unwrap();

        // test r8, r8
        rt.asm.test(r8, r8).unwrap();
        // jz ...
        rt.asm.jz(add_displ).unwrap();
    }

    // dec r8
    rt.asm.dec(r8).unwrap();
    // mov r8, [rcx + r8*8]
    rt.asm.mov(r8, ptr(rcx + r8 * 8)).unwrap();
    // imul r8, r9
    rt.asm.imul_2(r8, r9).unwrap();
    // add rax, r8
    rt.asm.add(rax, r8).unwrap();

    rt.asm.set_label(&mut add_displ).unwrap();
    {
        // movsxd r8, [rdx] -> displ
        rt.asm.movsxd(r8, dword_ptr(rdx)).unwrap();
        // add rax, r8
        rt.asm.add(rax, r8).unwrap();
        // add rdx, 0x4
        rt.asm.add(rdx, 0x4).unwrap();
    }

    // movzx r8, [rdx] -> seg
    rt.asm.movzx(r8, byte_ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // test r8, r8
    rt.asm.test(r8, r8).unwrap();
    // jz ...
    rt.asm.jz(epilogue).unwrap();

    rt.asm.set_label(&mut add_seg).unwrap();
    {
        // add rax, gs:[0x30] -> NT_TIB *TEB->NT_TIB.Self
        rt.asm.add(rax, ptr(0x30).gs()).unwrap();
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // ret
        stack::ret(rt);
    }
}
