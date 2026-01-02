use iced_x86::code_asm::{ax, ptr, r8w, r9b, rdx};

use crate::{
    runtime::{FnDef, Runtime},
    vm::stack,
};

// void (unsigned long*, unsigned long*, unsigned short, byte)
pub fn build(rt: &mut Runtime) {
    let mut sub = rt.asm.create_label();
    let mut done = rt.asm.create_label();

    // mov ax, [rdx]
    rt.asm.mov(ax, ptr(rdx)).unwrap();

    // test r9b, 0x1 -> sub
    rt.asm.test(r9b, 0x1).unwrap();
    // jnz ...
    rt.asm.jnz(sub).unwrap();

    // add ax, r8b
    rt.asm.add(ax, r8w).unwrap();
    // jmp ...
    rt.asm.jmp(done).unwrap();

    rt.asm.set_label(&mut sub).unwrap();
    {
        // sub ax, r8b
        rt.asm.sub(ax, r8w).unwrap();
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

        // mov [rdx], ax
        rt.asm.mov(ptr(rdx), ax).unwrap();

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
