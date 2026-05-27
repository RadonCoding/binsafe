use crate::{
    runtime::{FnDef, Runtime},
    vm::stack,
};
use iced_x86::code_asm::{
    al, ax, eax, ptr, r8, r8b, r8d, r8w, r9b, rax, rdx, AsmRegister16, AsmRegister32,
    AsmRegister64, AsmRegister8,
};

pub enum OperandSize {
    Byte(AsmRegister8, AsmRegister8),
    Word(AsmRegister16, AsmRegister16),
    Dword(AsmRegister32, AsmRegister32),
    Qword(AsmRegister64, AsmRegister64),
}

pub fn build_8(rt: &mut Runtime) {
    build(rt, OperandSize::Byte(al, r8b));
}

pub fn build_16(rt: &mut Runtime) {
    build(rt, OperandSize::Word(ax, r8w));
}

pub fn build_32(rt: &mut Runtime) {
    build(rt, OperandSize::Dword(eax, r8d));
}

pub fn build_64(rt: &mut Runtime) {
    build(rt, OperandSize::Qword(rax, r8));
}

fn build(rt: &mut Runtime, size: OperandSize) {
    let mut sub = rt.asm.create_label();
    let mut done = rt.asm.create_label();

    match size {
        OperandSize::Byte(reg_a, _) => {
            // mov al, [rdx]
            rt.asm.mov(reg_a, ptr(rdx)).unwrap();
        }
        OperandSize::Word(reg_a, _) => {
            // mov ax, [rdx]
            rt.asm.mov(reg_a, ptr(rdx)).unwrap();
        }
        OperandSize::Dword(reg_a, _) => {
            // mov eax, [rdx]
            rt.asm.mov(reg_a, ptr(rdx)).unwrap();
        }
        OperandSize::Qword(reg_a, _) => {
            // mov rax, [rdx]
            rt.asm.mov(reg_a, ptr(rdx)).unwrap();
        }
    };

    // test r9b, 0x1 -> sub
    rt.asm.test(r9b, 0x1).unwrap();
    // jnz ...
    rt.asm.jnz(sub).unwrap();

    match size {
        OperandSize::Byte(reg_a, reg_b) => {
            // add al, r8b
            rt.asm.add(reg_a, reg_b).unwrap();
        }
        OperandSize::Word(reg_a, reg_b) => {
            // add ax, r8b
            rt.asm.add(reg_a, reg_b).unwrap();
        }
        OperandSize::Dword(reg_a, reg_b) => {
            // add eax, r8d
            rt.asm.add(reg_a, reg_b).unwrap();
        }
        OperandSize::Qword(reg_a, reg_b) => {
            // add rax, r8
            rt.asm.add(reg_a, reg_b).unwrap();
        }
    };
    // jmp ...
    rt.asm.jmp(done).unwrap();

    rt.asm.set_label(&mut sub).unwrap();
    match size {
        OperandSize::Byte(reg_a, reg_b) => {
            // sub al, r8b
            rt.asm.sub(reg_a, reg_b).unwrap();
        }
        OperandSize::Word(reg_a, reg_b) => {
            // sub ax, r8b
            rt.asm.sub(reg_a, reg_b).unwrap();
        }
        OperandSize::Dword(reg_a, reg_b) => {
            // sub eax, r8d
            rt.asm.sub(reg_a, reg_b).unwrap();
        }
        OperandSize::Qword(reg_a, reg_b) => {
            // sub rax, r8
            rt.asm.sub(reg_a, reg_b).unwrap();
        }
    };

    rt.asm.set_label(&mut done).unwrap();
    {
        let mut flags = rt.asm.create_label();

        // pushfq
        stack::pushfq(rt);

        // test r9b, 0x2 -> store
        rt.asm.test(r9b, 0x2).unwrap();
        // jz ...
        rt.asm.jz(flags).unwrap();

        match size {
            OperandSize::Byte(reg_a, _) => {
                // mov [rdx], al
                rt.asm.mov(ptr(rdx), reg_a).unwrap();
            }
            OperandSize::Word(reg_a, _) => {
                // mov [rdx], ax
                rt.asm.mov(ptr(rdx), reg_a).unwrap();
            }
            OperandSize::Dword(reg_a, _) => {
                let mut extend = rt.asm.create_label();

                // test r9b, 0x4 -> memory
                rt.asm.test(r9b, 0x4).unwrap();
                // jz ...
                rt.asm.jz(extend).unwrap();

                // mov [rdx], eax
                rt.asm.mov(ptr(rdx), reg_a).unwrap();
                // jmp ...
                rt.asm.jmp(flags).unwrap();

                rt.asm.set_label(&mut extend).unwrap();
                {
                    // mov [rdx], rax
                    rt.asm.mov(ptr(rdx), rax).unwrap();
                }
            }
            OperandSize::Qword(reg_a, _) => {
                // mov [rdx], rax
                rt.asm.mov(ptr(rdx), reg_a).unwrap();
            }
        };

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
