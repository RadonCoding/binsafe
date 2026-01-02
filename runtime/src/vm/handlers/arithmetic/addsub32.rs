use iced_x86::code_asm::{ah, ax, dword_ptr, eax, ptr, r8d, r9b, r9w, rdx};

use crate::{
    runtime::{FnDef, Runtime},
    vm::stack,
};

// void (unsigned long*, unsigned long*, unsigned long, unsigned short)
pub fn build(rt: &mut Runtime) {
    let mut sub = rt.asm.create_label();
    let mut done = rt.asm.create_label();
    let mut flags = rt.asm.create_label();

    // mov eax, [rdx]
    rt.asm.mov(eax, ptr(rdx)).unwrap();

    // test r9b, r9b
    rt.asm.test(r9b, r9b).unwrap();
    // jnz ...
    rt.asm.jnz(sub).unwrap();

    // add eax, r8d
    rt.asm.add(eax, r8d).unwrap();
    // jmp ...
    rt.asm.jmp(done).unwrap();

    rt.asm.set_label(&mut sub).unwrap();
    {
        // sub eax, r8d
        rt.asm.sub(eax, r8d).unwrap();
    }

    rt.asm.set_label(&mut done).unwrap();
    {
        // pushfq
        stack::pushfq(rt);

        // mov [rdx], eax
        rt.asm.mov(ptr(rdx), eax).unwrap();

        // mov ax, r9w
        rt.asm.mov(ax, r9w).unwrap();

        // test ah, ah
        rt.asm.test(ah, ah).unwrap();
        // jz ...
        rt.asm.jz(flags).unwrap();

        // mov dword ptr [rdx + 0x4], 0x0
        rt.asm.mov(dword_ptr(rdx + 0x4), 0x0i32).unwrap();

        rt.asm.set_label(&mut flags).unwrap();
        {
            // pop rdx
            stack::pop(rt, rdx);
            // call ...
            stack::call(rt, rt.func_labels[&FnDef::VmArithmeticFlags]);
            // ret
            stack::ret(rt);
        }
    }
}
