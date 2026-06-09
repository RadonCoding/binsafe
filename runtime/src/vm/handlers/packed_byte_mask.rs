use iced_x86::code_asm::{al, r8, r8d, rax, r12, rcx, xmm0, ymm0};

use crate::{
    runtime::Runtime,
    vm::utils::{self, scratch},
};

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // al -> width
    utils::bytecode::read_byte(rt, rcx, al);

    utils::width::dispatch_vector(
        rt,
        al,
        &mut epilogue,
        |rt| {
            // load xmm0
            scratch::load_128(rt, r12, xmm0);
            // pmovmskb r8d, xmm0
            rt.asm.pmovmskb(r8d, xmm0).unwrap();
            // store r8
            scratch::store(rt, r12, r8);
        },
        |rt| {
            // load ymm0
            scratch::load_256(rt, r12, ymm0);
            // vpmovmskb r8d, ymm0
            rt.asm.vpmovmskb(r8d, ymm0).unwrap();
            // store r8
            scratch::store(rt, r12, r8);
        },
    );

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, rcx
        rt.asm.mov(rax, rcx).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
