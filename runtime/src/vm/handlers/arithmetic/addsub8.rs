use iced_x86::code_asm::{al, ptr, r8b, r9b, rdx};

use crate::{
    runtime::{FnDef, Runtime},

    vm::stack,
};

// void (unsigned long*, unsigned long*, byte, byte)
pub fn build(rt: &mut Runtime) {
    let mut sub = rt.asm.create_label();
    let mut done = rt.asm.create_label();

    // mov al, [rdx]
    rt.asm.mov(al, ptr(rdx)).unwrap();

    // test r9b, 0x1 -> sub
    rt.asm.test(r9b, 0x1).unwrap();
    // jnz ...
    rt.asm.jnz(sub).unwrap();

    // add al, r8b
    rt.asm.add(al, r8b).unwrap();
    // jmp ...
    rt.asm.jmp(done).unwrap();

    rt.asm.set_label(&mut sub).unwrap();
    {
        // sub al, r8b
        rt.asm.sub(al, r8b).unwrap();
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

        // mov [rdx], al
        rt.asm.mov(ptr(rdx), al).unwrap();

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
