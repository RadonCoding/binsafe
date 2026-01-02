use iced_x86::code_asm::{eax, ptr, r8d, r9b, rax, rdx};

use crate::{
    runtime::{FnDef, Runtime},
    vm::stack,
};

// void (unsigned long*, unsigned long*, unsigned int, byte)
pub fn build(rt: &mut Runtime) {
    let mut sub = rt.asm.create_label();
    let mut done = rt.asm.create_label();

    // mov eax, [rdx]
    rt.asm.mov(eax, ptr(rdx)).unwrap();

    // test r9b, 0x1 -> sub
    rt.asm.test(r9b, 0x1).unwrap();
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
        let mut flags = rt.asm.create_label();

        // pushfq
        stack::pushfq(rt);

        // test r9b, 0x2 -> store
        rt.asm.test(r9b, 0x2).unwrap();
        // jz ...
        rt.asm.jz(flags).unwrap();

        // mov [rdx], rax
        rt.asm.mov(ptr(rdx), rax).unwrap();

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
