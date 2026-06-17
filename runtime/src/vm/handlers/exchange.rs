use iced_x86::code_asm::{eax, ptr, r12, r8, r9, r9b, r9d, r9w, rax, rcx};

use crate::{
    runtime::Runtime,
    vm::utils::{self, scratch},
};

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // eax -> width
    utils::bytecode::read_byte_zx(rt, rcx, eax);

    // load r8
    scratch::load(rt, r12, r8);
    // load r9
    scratch::load(rt, r12, r9);

    utils::width::dispatch(
        rt,
        rax,
        &mut epilogue,
        Some(Box::new(|rt| {
            // xchg [r8], r9
            rt.asm.xchg(ptr(r8), r9).unwrap();
        })),
        Some(Box::new(|rt| {
            // xchg [r8], r9d
            rt.asm.xchg(ptr(r8), r9d).unwrap();
        })),
        None,
        Some(Box::new(|rt| {
            // xchg [r8], r9w
            rt.asm.xchg(ptr(r8), r9w).unwrap();
        })),
        None,
        Some(Box::new(|rt| {
            // xchg [r8], r9b
            rt.asm.xchg(ptr(r8), r9b).unwrap();
        })),
        None,
        None,
        None,
        None,
        None,
        None,
    );

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // store r9
        scratch::store(rt, r12, r9);

        // mov rax, rcx
        rt.asm.mov(rax, rcx).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
