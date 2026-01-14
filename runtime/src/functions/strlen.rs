use iced_x86::code_asm::{byte_ptr, rax, rcx};

use crate::runtime::Runtime;

// unsigned long (char*)
pub fn build(rt: &mut Runtime) {
    let mut counter_loop = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // mov rax, rcx
    rt.asm.mov(rax, rcx).unwrap();

    rt.asm.set_label(&mut counter_loop).unwrap();
    {
        // cmp [rax], 0x0
        rt.asm.cmp(byte_ptr(rax), 0x0).unwrap();
        // je ...
        rt.asm.je(epilogue).unwrap();
        // inc rcx
        rt.asm.inc(rax).unwrap();
        // jmp ...
        rt.asm.jmp(counter_loop).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // sub rax, rcx
        rt.asm.sub(rax, rcx).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
