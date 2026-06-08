use iced_x86::code_asm::{al, r8, r8d, rax, rdx, xmm0, ymm0};

use crate::{
    runtime::Runtime,
    vm::utils::{self, scratch, stack},
};

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    // al -> width
    utils::bytecode::read_byte(rt, rdx, al);

    utils::width::dispatch_vector(
        rt,
        al,
        &mut epilogue,
        |rt| {
            // load xmm0
            scratch::load_128(rt, xmm0);
            // pmovmskb r8d, xmm0
            rt.asm.pmovmskb(r8d, xmm0).unwrap();
            // store r8
            scratch::store(rt, r8);
        },
        |rt| {
            // load ymm0
            scratch::load_256(rt, ymm0);
            // vpmovmskb r8d, ymm0
            rt.asm.vpmovmskb(r8d, ymm0).unwrap();
            // store r8
            scratch::store(rt, r8);
        },
    );

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();
        // ret
        stack::ret(rt);
    }
}
