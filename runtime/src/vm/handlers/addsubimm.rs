use iced_x86::code_asm::{
    al, byte_ptr, dword_ptr, ptr, r12, r12b, r13, r13b, r13d, r13w, r14, r14b, r14d, r14w, r15, r8,
    r9, rax, rcx, rdx,
};

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::{VMBits, VMFlag, VMReg},
        stack, utils,
    },
};

macro_rules! arithmetic {
    (
        $rt:expr,
        $label:expr,
        $epilogue:expr,
        $src:ident,
        $dst:ident,
        $offset:expr,
        $size:expr,
        $is_32:expr
    ) => {
        $rt.asm.set_label(&mut $label).unwrap();
        {
            let mut sub = $rt.asm.create_label();
            let mut done = $rt.asm.create_label();

            // mov ..., [rcx + r8*8 + ...]
            $rt.asm.mov($dst, ptr(rcx + r8 * 8 + $offset)).unwrap();

            // mov ..., [rdx]
            $rt.asm.mov($src, ptr(rdx)).unwrap();
            // add rdx, ...
            $rt.asm.add(rdx, $size as i32).unwrap();

            // test r12b, r12b
            $rt.asm.test(r12b, r12b).unwrap();
            // jnz ...
            $rt.asm.jnz(sub).unwrap();

            // add ..., ...
            $rt.asm.add($dst, $src).unwrap();
            // jmp ...
            $rt.asm.jmp(done).unwrap();

            $rt.asm.set_label(&mut sub).unwrap();
            {
                // sub ..., ...
                $rt.asm.sub($dst, $src).unwrap();
            }

            $rt.asm.set_label(&mut done).unwrap();
            {
                if $is_32 {
                    // mov [rcx + r8*8 + 0x4], 0x0
                    $rt.asm.mov(dword_ptr(rcx + r8 * 8 + 0x4), 0x0i32).unwrap();
                }

                // mov [rcx + r8*8], ...
                $rt.asm.mov(ptr(rcx + r8 * 8 + $offset), $dst).unwrap();

                // pushfq
                stack::pushfq($rt);
                // pop r15
                stack::pop($rt, r15);

                // mov r8, [rcx + ...]
                utils::mov_reg_vreg_64($rt, rcx, VMReg::Flags, r8);

                const FLAG_MASK: u64 = (1 << VMFlag::Carry as u64)
                    | (1 << VMFlag::Parity as u64)
                    | (1 << VMFlag::Auxfiliary as u64)
                    | (1 << VMFlag::Zero as u64)
                    | (1 << VMFlag::Sign as u64)
                    | (1 << VMFlag::Overflow as u64);

                // mov r9, ...
                $rt.asm.mov(r9, !FLAG_MASK).unwrap();
                // and r8, r9
                $rt.asm.and(r8, r9).unwrap();

                // mov r9, ...
                $rt.asm.mov(r9, FLAG_MASK).unwrap();
                // and r15, r9
                $rt.asm.and(r15, r9).unwrap();
                // or r8, r15
                $rt.asm.or(r8, r15).unwrap();

                // mov [rcx + ...], r8
                utils::mov_vreg_reg_64($rt, rcx, r8, VMReg::Flags);

                // jmp ...
                $rt.asm.jmp($epilogue).unwrap();
            }
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
    // push r14
    stack::push(rt, r14);
    // push r15
    stack::push(rt, r15);

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

    // mov r12b, [rdx] -> sub
    rt.asm.mov(r12b, ptr(rdx)).unwrap();
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

    arithmetic!(rt, lower8, epilogue, r13b, r14b, 0, 1, false);
    arithmetic!(rt, higher8, epilogue, r13b, r14b, 1, 1, false);
    arithmetic!(rt, lower16, epilogue, r13w, r14w, 0, 2, false);
    arithmetic!(rt, lower32, epilogue, r13d, r14d, 0, 4, true);
    arithmetic!(rt, lower64, epilogue, r13, r14, 0, 8, false);

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // pop r15
        stack::pop(rt, r15);
        // pop r14
        stack::pop(rt, r14);
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
