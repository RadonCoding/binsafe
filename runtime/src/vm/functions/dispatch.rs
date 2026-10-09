use iced_x86::code_asm::{
    al, byte_ptr, dword_ptr, eax, edx, ptr, r12, r13, r14, r8, r8d, r9, r9d, rax, rcx, rdx, rsp,
    CodeLabel,
};

use crate::{
    mapper::Mappable,
    runtime::{DataDef, FnDef, ImportDef, Runtime, StringDef},
    vm::{
        bytecode::{VMCode, VMReg},
        handlers,
        utils::{bytecode, lock, register},
    },
    VM_DISPATCH_SIZE, VM_INTEGRITY_QWORD, VM_REDIRECT_SIZE, VM_TRAMPOLINE_SIZE,
};

#[cfg(feature = "profile")]
use crate::debug::{start_profiling, stop_profiling};

pub fn build(rt: &mut Runtime) {
    let mut setup_block = rt.asm.create_label();
    let mut resume_block = rt.asm.create_label();
    let mut decrypt_block = rt.asm.create_label();
    let mut start_block = rt.asm.create_label();
    let mut execute_loop = rt.asm.create_label();
    let mut check_loop = rt.asm.create_label();
    let mut check_suspend = rt.asm.create_label();
    let mut check_exit = rt.asm.create_label();
    let mut resolved = rt.asm.create_label();
    let mut trampoline = rt.asm.create_label();
    let mut lookup = rt.asm.create_label();
    let mut tamper = rt.asm.create_label();
    let mut terminate = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();

    // sub rsp, 0x28
    rt.asm.sub(rsp, 0x28).unwrap();

    rt.asm.set_label(&mut setup_block).unwrap();
    {
        // Initialize block pointer and block length:
        // mov r13, [r12 + ...]
        register::load(rt, r12, r13, VMReg::BPointer);
        // eax = length
        bytecode::read_word_zx(rt, r13, eax);
        // mov [r12 + ...], rax
        register::store(rt, r12, VMReg::BLength, rax);

        // Store the end of the block:
        // lea r14, [r13 + rax]
        rt.asm.lea(r14, ptr(r13 + rax)).unwrap();

        // Check if this is a fresh execution:
        // cmp [r12 + ...], 0x0
        register::cmp_with_native(rt, r12, VMReg::BResume, 0x0);
        // je ...
        rt.asm.je(decrypt_block).unwrap();
    }

    rt.asm.set_label(&mut resume_block).unwrap();
    {
        // mov r13, [r12 + ...]
        register::load(rt, r12, r13, VMReg::BResume);

        // mov [r12 + ...], 0x0
        register::store(rt, r12, VMReg::NBranch, 0x0);
        // mov [r12 + ...], 0x0
        register::store(rt, r12, VMReg::BResume, 0x0);

        // jmp ...
        rt.asm.jmp(execute_loop).unwrap();
    }

    rt.asm.set_label(&mut decrypt_block).unwrap();
    {
        #[cfg(feature = "profile")]
        start_profiling(rt);

        // Decrypt the block:
        // mov rcx, 0x1
        rt.asm.mov(rcx, 0x1u64).unwrap();
        // call ...
        rt.asm.call(rt.function_labels[&FnDef::VmCrypt]).unwrap();

        #[cfg(feature = "profile")]
        stop_profiling(rt, FnDef::VmCrypt, "decrypt");

        // mov rax, ...
        rt.asm.mov(rax, VM_INTEGRITY_QWORD).unwrap();
        // cmp [r14], rax
        rt.asm.cmp(ptr(r14), rax).unwrap();
        // jne ...
        rt.asm.jne(tamper).unwrap();
    }

    rt.asm.set_label(&mut start_block).unwrap();
    {
        // mov [r12 + ...], 0x0
        register::store(rt, r12, VMReg::NBranch, 0x0);

        // lea rax, [...]
        rt.asm
            .lea(rax, ptr(rt.data_labels[&DataDef::VmCodeStart]))
            .unwrap();
        // movsxd rcx, [rax]
        rt.asm.movsxd(rcx, ptr(rax)).unwrap();
        // add rax, rcx
        rt.asm.add(rax, rcx).unwrap();
        // mov rcx, r13
        rt.asm.mov(rcx, r13).unwrap();
        // sub rcx, 0x2
        rt.asm.sub(rcx, 0x2).unwrap();
        // sub rcx, rax
        rt.asm.sub(rcx, rax).unwrap();
        // mov [r12 + ...], rcx
        register::store(rt, r12, VMReg::VImmAdd, rcx);
        // or rcx, 0x1
        rt.asm.or(rcx, 0x1).unwrap();
        // mov [r12 + ...], rcx
        register::store(rt, r12, VMReg::VImmMul, rcx);
    }

    rt.asm.set_label(&mut execute_loop).unwrap();
    {
        // cmp r13, r14
        rt.asm.cmp(r13, r14).unwrap();
        // je ...
        rt.asm.je(check_loop).unwrap();

        // cmp [r12 + ...], 0x0
        register::cmp_with_native(rt, r12, VMReg::NBranch, 0x0);
        // jne ...
        rt.asm.jne(check_suspend).unwrap();

        // r8d -> operation
        bytecode::read_byte_zx(rt, r13, r8d);

        #[cfg(feature = "profile")]
        {
            use crate::debug::print_thread_message;

            let mut epilogue = rt.asm.create_label();

            let mut cases = Vec::new();

            for op in VMCode::VARIANTS {
                cases.push((rt.mapper.index(*op), rt.asm.create_label()));
            }

            rt.jumps(r8, cases.clone());

            for (op, (_, mut label)) in VMCode::VARIANTS.iter().zip(cases) {
                rt.asm.set_label(&mut label).unwrap();

                print_thread_message(rt, &format!("{:?}", op), None, None);

                rt.asm.jmp(epilogue).unwrap();
            }

            rt.asm.set_label(&mut epilogue).unwrap();
        }

        // mov rcx, r13
        rt.asm.mov(rcx, r13).unwrap();

        let cases = VMCode::VARIANTS
            .iter()
            .map(|&op| {
                let label = rt.function_labels[&handlers::handler(op)];
                (rt.mapper.index(op), label)
            })
            .collect::<Vec<(u8, CodeLabel)>>();

        rt.calls(r8, cases);

        // mov r13, rax
        rt.asm.mov(r13, rax).unwrap();

        // jmp ...
        rt.asm.jmp(execute_loop).unwrap();
    }

    rt.asm.set_label(&mut check_loop).unwrap();
    {
        // Skip if the native branch is zero:
        // cmp [r12 + ...], 0x0
        register::cmp_with_native(rt, r12, VMReg::NBranch, 0x0);
        // je ...
        rt.asm.je(check_exit).unwrap();

        // Skip if the native entry is not equal to the native branch:
        // mov rax, [r12 + ...]
        register::load(rt, r12, rax, VMReg::NEntry);
        // cmp [r12 + ...],
        register::cmp_with_native(rt, r12, VMReg::NBranch, rax);
        // jne ...
        rt.asm.jne(check_exit).unwrap();

        // Native branch points to the native entry so re-execute the block:
        // mov r13, [...]
        register::load(rt, r12, r13, VMReg::BPointer);
        // eax = length
        bytecode::read_word_zx(rt, r13, eax);
        // mov [r12 + ...], rax
        register::store(rt, r12, VMReg::BLength, rax);
        // jmp ...
        rt.asm.jmp(start_block).unwrap();
    }

    rt.asm.set_label(&mut check_suspend).unwrap();
    {
        // cmp r13, r14
        rt.asm.cmp(r13, r14).unwrap();
        // je ...
        rt.asm.je(check_exit).unwrap();

        // mov [r12 + ...], r13
        register::store(rt, r12, VMReg::BResume, r13);
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut check_exit).unwrap();
    {
        #[cfg(feature = "profile")]
        start_profiling(rt);

        // Re-encrypt the current block:
        // xor rcx, rcx
        rt.asm.xor(rcx, rcx).unwrap();
        // call ...
        rt.asm.call(rt.function_labels[&FnDef::VmCrypt]).unwrap();

        #[cfg(feature = "profile")]
        stop_profiling(rt, FnDef::VmCrypt, "encrypt");

        // Compute the address where execution will continue:
        // mov rax, [r12 + ...]
        register::load(rt, r12, rax, VMReg::NExit);
        // mov rcx, [r12 + ...]
        register::load(rt, r12, rcx, VMReg::NBranch);
        // test rcx, rcx
        rt.asm.test(rcx, rcx).unwrap();
        // cmovnz rax, rcx
        rt.asm.cmovnz(rax, rcx).unwrap();
        // test rax, rax
        rt.asm.test(rax, rax).unwrap();
        // je ...
        rt.asm.je(epilogue).unwrap();

        // Follow an indirect CALL rel32 entry into its trampoline:
        // cmp [rax], 0xE8
        rt.asm.cmp(byte_ptr(rax), 0xE8).unwrap();
        // jne ...
        rt.asm.jne(resolved).unwrap();
        // movsxd r9, [rax + 0x1]
        rt.asm.movsxd(r9, dword_ptr(rax + 0x1)).unwrap();
        // lea rax, [rax + ...]
        rt.asm.lea(rax, ptr(rax + VM_TRAMPOLINE_SIZE)).unwrap();
        // add rax, r9
        rt.asm.add(rax, r9).unwrap();

        rt.asm.set_label(&mut resolved).unwrap();
        {
            // cmp [rax], 0x68
            rt.asm.cmp(byte_ptr(rax), 0x68).unwrap();
            // jne ...
            rt.asm.jne(trampoline).unwrap();

            // mov edx, [rax + 0x1]
            rt.asm.mov(edx, ptr(rax + 0x1)).unwrap();
            // add rax, ...
            rt.asm.add(rax, VM_DISPATCH_SIZE as i32).unwrap();
            // jmp ...
            rt.asm.jmp(lookup).unwrap();
        }

        rt.asm.set_label(&mut trampoline).unwrap();
        {
            // cmp [rax], 0xC7
            rt.asm.cmp(byte_ptr(rax), 0xC7).unwrap();
            // jne ...
            rt.asm.jne(epilogue).unwrap();

            // mov edx, [rax + 0x3]
            rt.asm.mov(edx, ptr(rax + 0x3)).unwrap();
            // add rax, ...
            rt.asm.add(rax, VM_REDIRECT_SIZE as i32).unwrap();
        }

        rt.asm.set_label(&mut lookup).unwrap();
        {
            // mov rcx, rax
            rt.asm.mov(rcx, rax).unwrap();
            // call ...
            rt.asm.call(rt.function_labels[&FnDef::VmLookup]).unwrap();
            // mov [r12 + ...], rax
            register::store(rt, r12, VMReg::BPointer, rax);

            // jmp ...
            rt.asm.jmp(setup_block).unwrap();
        }
    }

    lock::acquire_global(rt, al, Some(&mut tamper));
    {
        // mov rcx, [...]; call ...
        rt.resolve(ImportDef::LoadLibraryA);

        // lea rcx, ...
        rt.asm
            .lea(rcx, ptr(rt.string_labels[&StringDef::User32]))
            .unwrap();
        // call rax
        rt.asm.call(rax).unwrap();

        // test rax, rax
        rt.asm.test(rax, rax).unwrap();
        // jz ...
        rt.asm.jz(terminate).unwrap();

        // mov rcx, [...]; call ...
        rt.resolve(ImportDef::MessageBoxA);

        // xor rcx, rcx
        rt.asm.xor(rcx, rcx).unwrap();
        // lea rdx, [...]
        rt.asm
            .lea(rdx, ptr(rt.string_labels[&StringDef::Tampered]))
            .unwrap();
        // xor r8d, r8d
        rt.asm.xor(r8, r8).unwrap();
        // mov r9d, ...  -> MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST | MB_SERVICE_NOTIFICATION
        rt.asm
            .mov(r9d, 0x00000010 | 0x00010000 | 0x00040000 | 0x00200000)
            .unwrap();
        // call rax
        rt.asm.call(rax).unwrap();

        rt.asm.set_label(&mut terminate).unwrap();
        {
            // mov rcx, [...]; call ...
            rt.resolve(ImportDef::NtTerminateProcess);
            // mov rcx, -0x1
            rt.asm.mov(rcx, -0x1i64).unwrap();
            // mov edx, 0xC0000001 -> STATUS_UNSUCCESSFUL
            rt.asm.mov(edx, 0xC0000001u32).unwrap();
            // call rax
            rt.asm.call(rax).unwrap();
        }
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // add rsp, 0x28
        rt.asm.add(rsp, 0x28).unwrap();

        // pop r14
        rt.asm.pop(r14).unwrap();
        // pop r13
        rt.asm.pop(r13).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
