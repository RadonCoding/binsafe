use iced_x86::code_asm::{eax, ecx, ptr, r13, r8, r9, rax, rcx, rdx};

use crate::runtime::{DataDef, Runtime};

// unsigned char* (unsigned long)
pub fn build(rt: &mut Runtime) {
    let mut search = rt.asm.create_label();
    let mut less = rt.asm.create_label();
    let mut greater = rt.asm.create_label();
    let mut found = rt.asm.create_label();
    let mut not_found = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r13
    rt.asm.push(r13).unwrap();

    // mov rax, gs:[0x60] -> PEB *TEB->ProcessEnvironmentBlock
    rt.asm.mov(rax, ptr(0x60).gs()).unwrap();
    // mov rax, [rax + 0x10] -> VOID *PEB->ImageBaseAddress
    rt.asm.mov(rax, ptr(rax + 0x10)).unwrap();

    // sub rcx, rax
    rt.asm.sub(rcx, rax).unwrap();

    // lea rax, [...]
    rt.asm
        .lea(rax, ptr(rt.data_labels[&DataDef::Bytecode]))
        .unwrap();
    // mov r13, [rax] -> number of entries
    rt.asm.mov(r13, ptr(rax)).unwrap();
    // add rax, 0x8
    rt.asm.add(rax, 0x8).unwrap();

    // xor r8, r8
    rt.asm.xor(r8, r8).unwrap();
    // mov r9, r13
    rt.asm.mov(r9, r13).unwrap();
    // dec r9
    rt.asm.dec(r9).unwrap();

    rt.asm.set_label(&mut search).unwrap();
    {
        // cmp r8, r9
        rt.asm.cmp(r8, r9).unwrap();
        // jg ...
        rt.asm.jg(not_found).unwrap();

        // mov rdx, r8
        rt.asm.mov(rdx, r8).unwrap();
        // add rdx, r9
        rt.asm.add(rdx, r9).unwrap();
        // shr rdx, 1
        rt.asm.shr(rdx, 1).unwrap();

        // cmp ecx, [rax + rdx*8] -> key
        rt.asm.cmp(ecx, ptr(rax + rdx * 8)).unwrap();
        // je ...
        rt.asm.je(found).unwrap();
        // jl ...
        rt.asm.jl(less).unwrap();

        rt.asm.set_label(&mut greater).unwrap();
        {
            // mov r8, rdx
            rt.asm.mov(r8, rdx).unwrap();
            // add r8, 1
            rt.asm.add(r8, 1).unwrap();
            // jmp ...
            rt.asm.jmp(search).unwrap();
        }

        rt.asm.set_label(&mut less).unwrap();
        {
            // mov r9, rdx
            rt.asm.mov(r9, rdx).unwrap();
            // sub r9, 1
            rt.asm.sub(r9, 1).unwrap();
            // jmp ...
            rt.asm.jmp(search).unwrap();
        }
    }

    rt.asm.set_label(&mut found).unwrap();
    {
        // lea r8, [rax + r13*8] -> bytecode
        rt.asm.lea(r8, ptr(rax + r13 * 8)).unwrap();
        // mov eax, [rax + rdx*8 + 4] -> offset
        rt.asm.mov(eax, ptr(rax + rdx * 8 + 4)).unwrap();
        // add r8, rax
        rt.asm.add(r8, rax).unwrap();
        // mov rax, r8
        rt.asm.mov(rax, r8).unwrap();
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut not_found).unwrap();
    {
        // xor rax, rax
        rt.asm.xor(rax, rax).unwrap();
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // pop r13
        rt.asm.pop(r13).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
