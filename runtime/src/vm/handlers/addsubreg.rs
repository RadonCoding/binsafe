use iced_x86::code_asm::{ah, al, byte_ptr, eax, ptr, r12, r12d, r13, r13b, r8, r9, rax, rcx, rdx};

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{VMBits, VMReg},
        stack, utils,
    },
};

macro_rules! arithmetic {
    ($rt:expr, $dst:ident, $src:ident) => {
        // test r13b, r13b
        $rt.asm.test(r13b, r13b).unwrap();

        let mut is_sub = $rt.asm.create_label();

        let mut done = $rt.asm.create_label();

        // jnz ...
        $rt.asm.jnz(is_sub).unwrap();
        // add ..., ...
        $rt.asm.add($dst, $src).unwrap();
        // jmp ...
        $rt.asm.jmp(done).unwrap();

        $rt.asm.set_label(&mut is_sub).unwrap();
        {
            // sub ..., ...
            $rt.asm.sub($dst, $src).unwrap();
        }

        $rt.asm.set_label(&mut done).unwrap();
        {
            // push rax
            stack::push($rt, rax);
            // push r8
            stack::push($rt, r8);

            // xor eax, eax
            $rt.asm.xor(eax, eax).unwrap();
            // setz al
            $rt.asm.setz(al).unwrap();
            // shl eax, 0x6
            $rt.asm.shl(eax, 0x6).unwrap();
            // mov r8, rax
            $rt.asm.mov(r8, rax).unwrap();

            // xor eax, eax
            $rt.asm.xor(eax, eax).unwrap();
            // sets al
            $rt.asm.sets(al).unwrap();
            // shl eax, 0x7
            $rt.asm.shl(eax, 0x7).unwrap();
            // or r8, rax
            $rt.asm.or(r8, rax).unwrap();

            // xor eax, eax
            $rt.asm.xor(eax, eax).unwrap();
            // setc al
            $rt.asm.setc(al).unwrap();
            // or r8, rax
            $rt.asm.or(r8, rax).unwrap();

            // mov ..., r8
            utils::mov_vreg_reg_64($rt, rcx, r8, VMReg::Flags);

            // pop r8
            stack::pop($rt, r8);
            // pop rax
            stack::pop($rt, rax);
        }
    };
}

// unsigned char* (unsigned long*, unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut lower8 = rt.asm.create_label();
    let mut higher8 = rt.asm.create_label();
    let mut lower16 = rt.asm.create_label();
    let mut lower32 = rt.asm.create_label();
    let mut lower64 = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r12
    stack::push(rt, r12);
    // push r13
    stack::push(rt, r13);

    // mov al, [rdx] -> bits
    rt.asm.mov(al, ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // movzx r8, [rdx] -> dst
    rt.asm.movzx(r8, byte_ptr(rdx)).unwrap();
    // dec r8
    rt.asm.dec(r8).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // movzx r9, [rdx] -> src
    rt.asm.movzx(r9, byte_ptr(rdx)).unwrap();
    // dec r9
    rt.asm.dec(r9).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // mov r13b, [rdx] -> sub
    rt.asm.mov(r13b, ptr(rdx)).unwrap();
    // add rdx, 0x1
    rt.asm.add(rdx, 0x1).unwrap();

    // cmp al, ...
    rt.asm.cmp(al, VMBits::Lower64 as u8 as i32).unwrap();
    // je ...
    rt.asm.je(lower64).unwrap();
    // cmp al, ...
    rt.asm.cmp(al, VMBits::Lower32 as u8 as i32).unwrap();
    // je ...
    rt.asm.je(lower32).unwrap();
    // cmp al, ...
    rt.asm.cmp(al, VMBits::Lower16 as u8 as i32).unwrap();
    // je ...
    rt.asm.je(lower16).unwrap();
    // cmp al, ...
    rt.asm.cmp(al, VMBits::Higher8 as u8 as i32).unwrap();
    // je ...
    rt.asm.je(higher8).unwrap();

    rt.asm.set_label(&mut lower8).unwrap();
    {
        // mov rax, [rcx + r9*8] -> src
        rt.asm.mov(rax, ptr(rcx + r9 * 8)).unwrap();
        // and rax, 0xFF
        rt.asm.and(rax, 0xFF).unwrap();

        // mov r12, [rcx + r8*8] -> dst
        rt.asm.mov(r12, ptr(rcx + r8 * 8)).unwrap();
        // mov r13, r12
        rt.asm.mov(r13, r12).unwrap();
        // and r12, 0xFF
        rt.asm.and(r12, 0xFF).unwrap();

        arithmetic!(rt, r12, rax);

        // and r12, 0xFF
        rt.asm.and(r12, 0xFF).unwrap();
        // and r13, !0xFF
        rt.asm.and(r13, !0xFFi32).unwrap();
        // or r13, r12
        rt.asm.or(r13, r12).unwrap();

        // mov [rcx + r8*8], r13
        rt.asm.mov(ptr(rcx + r8 * 8), r13).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut higher8).unwrap();
    {
        // mov rax, [rcx + r9*8] -> src
        rt.asm.mov(rax, ptr(rcx + r9 * 8)).unwrap();
        // and rax, 0xFF
        rt.asm.and(rax, 0xFF).unwrap();
        // shl rax, 0x8
        rt.asm.shl(rax, 0x8).unwrap();

        // mov r12, [rcx + r8*8] -> dst
        rt.asm.mov(r12, ptr(rcx + r8 * 8)).unwrap();
        // mov r13, r12
        rt.asm.mov(r13, r12).unwrap();
        // and r12, 0xFF00
        rt.asm.and(r12, 0xFF00i32).unwrap();

        arithmetic!(rt, r12, rax);

        // and r12, 0xFF00
        rt.asm.and(r12, 0xFF00i32).unwrap();
        // and r13, !0xFF00
        rt.asm.and(r13, !0xFF00i32).unwrap();
        // or r13, r12
        rt.asm.or(r13, r12).unwrap();

        // mov [rcx + r8*8], r13
        rt.asm.mov(ptr(rcx + r8 * 8), r13).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower16).unwrap();
    {
        // mov rax, [rcx + r9*8] -> src
        rt.asm.mov(rax, ptr(rcx + r9 * 8)).unwrap();
        // and rax, 0xFFFF
        rt.asm.and(rax, 0xFFFF).unwrap();

        // mov r12, [rcx + r8*8] -> dst
        rt.asm.mov(r12, ptr(rcx + r8 * 8)).unwrap();
        // mov r13, r12
        rt.asm.mov(r13, r12).unwrap();
        // and r12, 0xFFFF
        rt.asm.and(r12, 0xFFFF).unwrap();

        arithmetic!(rt, r12, rax);

        // and r12, 0xFFFF
        rt.asm.and(r12, 0xFFFF).unwrap();
        // and r13, !0xFFFF
        rt.asm.and(r13, !0xFFFFi32).unwrap();
        // or r13, r12
        rt.asm.or(r13, r12).unwrap();

        // mov [rcx + r8*8], r13
        rt.asm.mov(ptr(rcx + r8 * 8), r13).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower32).unwrap();
    {
        // mov eax, [rcx + r9 * 8] -> src
        rt.asm.mov(eax, ptr(rcx + r9 * 8)).unwrap();
        // mov r12d, [rcx + r8 * 8] -> dst
        rt.asm.mov(r12d, ptr(rcx + r8 * 8)).unwrap();

        arithmetic!(rt, r12d, eax);

        // mov [rcx + r8 * 8], r12
        rt.asm.mov(ptr(rcx + r8 * 8), r12).unwrap();

        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut lower64).unwrap();
    {
        // mov rax, [rcx + r9 * 8] -> src
        rt.asm.mov(rax, ptr(rcx + r9 * 8)).unwrap();
        // mov r12, [rcx + r8 * 8] -> dst
        rt.asm.mov(r12, ptr(rcx + r8 * 8)).unwrap();

        arithmetic!(rt, r12, rax);

        // mov [rcx + r8 * 8], r12
        rt.asm.mov(ptr(rcx + r8 * 8), r12).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // pop r13
        stack::pop(rt, r13);
        // pop r12
        stack::pop(rt, r12);
        // mov rax, rdx
        rt.asm.mov(rax, rdx).unwrap();
        // ret
        stack::ret(rt);
    }
}
