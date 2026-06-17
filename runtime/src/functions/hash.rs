use crate::runtime::Runtime;

use iced_x86::code_asm::{byte_ptr, r13, r8, rax, rcx, rdx, word_ptr};

// unsigned long (void*, bool)
pub fn build(rt: &mut Runtime) {
    let mut wide_loop = rt.asm.create_label();
    let mut ansi_loop = rt.asm.create_label();

    let mut epilogue = rt.asm.create_label();

    // push r13
    rt.asm.push(r13).unwrap();
    // mov r13, rdx
    rt.asm.mov(r13, rdx).unwrap();

    // mov rax, ...
    rt.asm.mov(rax, 0xcbf29ce484222325u64 ^ rt.nonce).unwrap();

    // test r13, r13
    rt.asm.test(r13, r13).unwrap();
    // jz ...
    rt.asm.jz(ansi_loop).unwrap();

    rt.asm.set_label(&mut wide_loop).unwrap();
    {
        // movzx rdx, word ptr [rcx]
        rt.asm.movzx(rdx, word_ptr(rcx)).unwrap();

        // test rdx, rdx
        rt.asm.test(rdx, rdx).unwrap();
        // jz ...
        rt.asm.jz(epilogue).unwrap();

        // and rdx, 0xff
        rt.asm.and(rdx, 0xff).unwrap();

        // xor rax, rdx
        rt.asm.xor(rax, rdx).unwrap();

        // mov r8, 0x100000001b3
        rt.asm.mov(r8, 0x100000001b3u64).unwrap();
        // imul rax, r8
        rt.asm.imul_2(rax, r8).unwrap();

        // add rcx, 0x2
        rt.asm.add(rcx, 0x2).unwrap();

        // jmp ...
        rt.asm.jmp(wide_loop).unwrap();
    }

    rt.asm.set_label(&mut ansi_loop).unwrap();
    {
        // movzx rdx, [rcx]
        rt.asm.movzx(rdx, byte_ptr(rcx)).unwrap();

        // test rdx, rdx
        rt.asm.test(rdx, rdx).unwrap();
        // jz ...
        rt.asm.jz(epilogue).unwrap();

        // xor rax, rdx
        rt.asm.xor(rax, rdx).unwrap();

        // mov r8, 0x100000001b3
        rt.asm.mov(r8, 0x100000001b3u64).unwrap();
        // mul r8
        rt.asm.mul(r8).unwrap();

        // inc rcx
        rt.asm.inc(rcx).unwrap();

        // jmp ...
        rt.asm.jmp(ansi_loop).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // mov rdx, rax
        rt.asm.mov(rdx, rax).unwrap();
        // shr rdx, 0x21
        rt.asm.shr(rdx, 0x21).unwrap();
        // xor rax, rdx
        rt.asm.xor(rax, rdx).unwrap();

        // mov r8, 0xff51afd7ed558ccd
        rt.asm.mov(r8, 0xff51afd7ed558ccdu64).unwrap();
        // mul r8
        rt.asm.mul(r8).unwrap();

        // mov rdx, rax
        rt.asm.mov(rdx, rax).unwrap();
        // shr rdx, 0x21
        rt.asm.shr(rdx, 0x21).unwrap();
        // xor rax, rdx
        rt.asm.xor(rax, rdx).unwrap();

        // mov r8, 0xc4ceb9fe1a85ec53
        rt.asm.mov(r8, 0xc4ceb9fe1a85ec53u64).unwrap();
        // mul r8
        rt.asm.mul(r8).unwrap();

        // mov rdx, rax
        rt.asm.mov(rdx, rax).unwrap();
        // shr rdx, 0x21
        rt.asm.shr(rdx, 0x21).unwrap();
        // xor rax, rdx
        rt.asm.xor(rax, rdx).unwrap();

        // pop r13
        rt.asm.pop(r13).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
