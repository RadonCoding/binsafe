use iced_x86::code_asm::{al, cl, ptr, r8, r9b, rcx, rdx};

use crate::{runtime::Runtime, vm::stack};

// void (unsigned long, unsigned char*, unsigned short, bool)
pub fn build(rt: &mut Runtime) {
    let mut crypt_loop = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();
    let mut update_key_decrypt = rt.asm.create_label();
    let mut continue_loop = rt.asm.create_label();

    // add r8, rdx
    rt.asm.add(r8, rdx).unwrap();

    rt.asm.set_label(&mut crypt_loop).unwrap();
    {
        // cmp rdx, r8
        rt.asm.cmp(rdx, r8).unwrap();
        // je ...
        rt.asm.je(epilogue).unwrap();

        // mov al, [rdx]
        rt.asm.mov(al, ptr(rdx)).unwrap();

        // xor [rdx], cl
        rt.asm.xor(ptr(rdx), cl).unwrap();

        // shl rcx, 0x8
        rt.asm.shl(rcx, 0x8).unwrap();

        // test r9b, r9b
        rt.asm.test(r9b, r9b).unwrap();
        // jnz ...
        rt.asm.jnz(update_key_decrypt).unwrap();

        // mov cl, [rdx]
        rt.asm.mov(cl, ptr(rdx)).unwrap();
        // jmp ...
        rt.asm.jmp(continue_loop).unwrap();

        rt.asm.set_label(&mut update_key_decrypt).unwrap();
        {
            // mov cl, al
            rt.asm.mov(cl, al).unwrap();
        }

        rt.asm.set_label(&mut continue_loop).unwrap();
        {
            // inc rdx
            rt.asm.inc(rdx).unwrap();
            // jmp ...
            rt.asm.jmp(crypt_loop).unwrap();
        }
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // ret
        stack::ret(rt);
    }
}
