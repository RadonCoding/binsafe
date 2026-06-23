use iced_x86::code_asm::{
    al, byte_ptr, dword_ptr, eax, edx, ptr, qword_ptr, r12, r13, r14, r8, r8d, r9, r9d, rax, rcx,
    rdx, rsp, CodeLabel,
};

use crate::{
    mapper::Mappable,
    runtime::{FnDef, ImportDef, Runtime, StringDef},
    vm::{
        bytecode::{VMOp, VMReg},
        utils::{self, lock},
    },
    VM_DISPATCH_SIZE, VM_INTEGRITY_QWORD, VM_TRAMPOLINE_SIZE,
};

#[cfg(feature = "profile")]
use crate::debug::{start_profiling, stop_profiling};

const HANDLERS: [(VMOp, FnDef); VMOp::COUNT] = [
    (VMOp::Jcc, FnDef::VmHandlerJcc),
    (VMOp::Ret, FnDef::VmHandlerRet),
    (VMOp::LoadImmediate, FnDef::VmHandlerLoadImmediate),
    (VMOp::LoadRegister, FnDef::VmHandlerLoadRegister),
    (VMOp::LoadMemory, FnDef::VmHandlerLoadMemory),
    (VMOp::LoadAddress, FnDef::VmHandlerLoadAddress),
    (VMOp::StoreRegister, FnDef::VmHandlerStoreRegister),
    (VMOp::StoreMemory, FnDef::VmHandlerStoreMemory),
    (VMOp::LoadVector, FnDef::VmHandlerLoadVector),
    (VMOp::StoreMerge, FnDef::VmHandlerStoreMerge),
    (VMOp::StoreExtend, FnDef::VmHandlerStoreExtend),
    (VMOp::Add, FnDef::VmHandlerAdd),
    (VMOp::Sub, FnDef::VmHandlerSub),
    (VMOp::Exchange, FnDef::VmHandlerExchange),
    (VMOp::ExchangeAdd, FnDef::VmHandlerExchangeAdd),
    (VMOp::CompareExchange, FnDef::VmHandlerCompareExchange),
    (VMOp::And, FnDef::VmHandlerAnd),
    (VMOp::Or, FnDef::VmHandlerOr),
    (VMOp::Xor, FnDef::VmHandlerXor),
    (VMOp::Rol, FnDef::VmHandlerRol),
    (VMOp::Ror, FnDef::VmHandlerRor),
    (VMOp::Shl, FnDef::VmHandlerShl),
    (VMOp::Shr, FnDef::VmHandlerShr),
    (VMOp::Sar, FnDef::VmHandlerSar),
    (VMOp::Mul, FnDef::VmHandlerMul),
    (VMOp::Div, FnDef::VmHandlerDiv),
    (VMOp::TrailingZeros, FnDef::VmHandlerTrailingZeros),
    (VMOp::BitScanReverse, FnDef::VmHandlerBitScanReverse),
    (VMOp::ByteSwap, FnDef::VmHandlerByteSwap),
    (VMOp::BitTest, FnDef::VmHandlerBitTest),
    (VMOp::BitTestSet, FnDef::VmHandlerBitTestSet),
    (VMOp::BitTestReset, FnDef::VmHandlerBitTestReset),
    (VMOp::BitTestComplement, FnDef::VmHandlerBitTestComplement),
    (VMOp::Push, FnDef::VmHandlerPush),
    (VMOp::Pop, FnDef::VmHandlerPop),
    (VMOp::Discard, FnDef::VmHandlerDiscard),
    (VMOp::PackedByteMask, FnDef::VmHandlerPackedByteMask),
    (VMOp::PackedByteEqual, FnDef::VmHandlerPackedByteEqual),
    (VMOp::VectorAnd, FnDef::VmHandlerVectorAnd),
    (VMOp::VectorAndNot, FnDef::VmHandlerVectorAndNot),
    (VMOp::VectorOr, FnDef::VmHandlerVectorOr),
    (VMOp::VectorXor, FnDef::VmHandlerVectorXor),
    (VMOp::VectorAdd, FnDef::VmHandlerVectorAdd),
    (VMOp::VectorSub, FnDef::VmHandlerVectorSub),
    (VMOp::VectorMul, FnDef::VmHandlerVectorMul),
    (VMOp::VectorDiv, FnDef::VmHandlerVectorDiv),
    (VMOp::Timestamp, FnDef::VmHandlerTimestamp),
];

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
    let mut tamper = rt.asm.create_label();
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
        utils::vreg::load_reg(rt, r12, VMReg::BPointer, r13);
        // eax = length
        utils::bytecode::read_word_zx(rt, r13, eax);
        // mov [r12 + ...], rax
        utils::vreg::store_reg(rt, r12, rax, VMReg::BLength);

        // Store the end of the block:
        // lea r14, [r13 + rax]
        rt.asm.lea(r14, ptr(r13 + rax)).unwrap();

        // Check if this is a fresh execution:
        // cmp [r12 + ...], 0x0
        utils::vreg::cmp_imm(rt, r12, VMReg::BResume, 0x0);
        // je ...
        rt.asm.je(decrypt_block).unwrap();
    }

    rt.asm.set_label(&mut resume_block).unwrap();
    {
        // mov r13, [r12 + ...]
        utils::vreg::load_reg(rt, r12, VMReg::BResume, r13);

        // mov [r12 + ...], 0x0
        utils::vreg::store_imm(rt, r12, 0x0, VMReg::NBranch);
        // mov [r12 + ...], 0x0
        utils::vreg::store_imm(rt, r12, 0x0, VMReg::BResume);

        // jmp ...
        rt.asm.jmp(execute_loop).unwrap();
    }

    rt.asm.set_label(&mut decrypt_block).unwrap();
    {
        #[cfg(feature = "profile")]
        start_profiling(rt, "vm_crypt_decrypt");

        // Decrypt the block:
        // mov rcx, 0x1
        rt.asm.mov(rcx, 0x1u64).unwrap();
        // call ...
        rt.asm.call(rt.function_labels[&FnDef::VmCrypt]).unwrap();

        #[cfg(feature = "profile")]
        stop_profiling(rt, "vm_crypt_decrypt");

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
        utils::vreg::store_imm(rt, r12, 0x0, VMReg::NBranch);
        // mov [r12 + ...], 0x0
        utils::vreg::store_imm(rt, r12, 0x0, VMReg::VImm);
    }

    rt.asm.set_label(&mut execute_loop).unwrap();
    {
        // cmp r13, r14
        rt.asm.cmp(r13, r14).unwrap();
        // je ...
        rt.asm.je(check_loop).unwrap();

        // cmp [r12 + ...], 0x0
        utils::vreg::cmp_imm(rt, r12, VMReg::NBranch, 0x0);
        // jne ...
        rt.asm.jne(check_suspend).unwrap();

        // r8d -> operation
        utils::bytecode::read_byte_zx(rt, r13, r8d);

        // mov rcx, r13
        rt.asm.mov(rcx, r13).unwrap();

        let cases = HANDLERS
            .iter()
            .map(|&(op, def)| (rt.mapper.index(op), rt.function_labels[&def]))
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
        utils::vreg::cmp_imm(rt, r12, VMReg::NBranch, 0x0);
        // je ...
        rt.asm.je(check_suspend).unwrap();

        // Skip if the native entry is not equal to the native branch:
        // mov rax, [r12 + ...]
        utils::vreg::load_reg(rt, r12, VMReg::NEntry, rax);
        // cmp [r12 + ...],
        utils::vreg::cmp_reg(rt, r12, VMReg::NBranch, rax);
        // jne ...
        rt.asm.jne(check_suspend).unwrap();

        // Native branch points to the native entry so re-execute the block:
        // mov r13, [...]
        utils::vreg::load_reg(rt, r12, VMReg::BPointer, r13);
        // eax = length
        utils::bytecode::read_word_zx(rt, r13, eax);
        // mov [r12 + ...], rax
        utils::vreg::store_reg(rt, r12, rax, VMReg::BLength);
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
        utils::vreg::store_reg(rt, r12, r13, VMReg::BResume);
        // jmp ...
        rt.asm.jmp(epilogue).unwrap();
    }

    rt.asm.set_label(&mut check_exit).unwrap();
    {
        #[cfg(feature = "profile")]
        start_profiling(rt, "vm_crypt_encrypt");

        // Re-encrypt the current block:
        // xor rcx, rcx
        rt.asm.xor(rcx, rcx).unwrap();
        // call ...
        rt.asm.call(rt.function_labels[&FnDef::VmCrypt]).unwrap();

        #[cfg(feature = "profile")]
        stop_profiling(rt, "vm_crypt_encrypt");

        // Point block pointer at the next block:
        // mov rax, [r12 + ...]
        utils::vreg::load_reg(rt, r12, VMReg::BLength, rax);
        // not rax
        rt.asm.not(rax).unwrap();
        // and rax, 0x7
        rt.asm.and(rax, 0x7).unwrap();
        // +1 for integrity +1 for state +1 for lock:
        // lea rax, [r13 + rax + 0x1 + 0x1 + 0x1]
        rt.asm.lea(rax, ptr(r13 + rax + 0x1 + 0x1 + 0x1)).unwrap();
        // mov [r12 + ...], rax
        utils::vreg::store_reg(rt, r12, rax, VMReg::BPointer);

        // If there's no branch target, advance to next block:
        // mov rax, [r12 + ...]
        utils::vreg::load_reg(rt, r12, VMReg::NExit, rax);
        // mov rcx, [r12 + ...]
        utils::vreg::load_reg(rt, r12, VMReg::NBranch, rcx);
        // test rcx, rcx
        rt.asm.test(rcx, rcx).unwrap();
        // cmovnz rax, rcx
        rt.asm.cmovnz(rax, rcx).unwrap();
        // test rax, rax
        rt.asm.test(rax, rax).unwrap();
        // je ...
        rt.asm.je(epilogue).unwrap();

        // Follow an indirect JMP rel32 entry into its trampoline:
        // cmp [rax], 0xE9
        rt.asm.cmp(byte_ptr(rax), 0xE9).unwrap();
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
            rt.asm.jne(epilogue).unwrap();

            // mov edx, [rax + 0x1]
            rt.asm.mov(edx, ptr(rax + 0x1)).unwrap();

            // add rax, ...
            rt.asm.add(rax, VM_DISPATCH_SIZE as i32).unwrap();

            // mov rcx, rax
            rt.asm.mov(rcx, rax).unwrap();
            // call ...
            rt.asm.call(rt.function_labels[&FnDef::VmLookup]).unwrap();
            // mov [r12 + ...], rax
            utils::vreg::store_reg(rt, r12, rax, VMReg::BPointer);

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
        // mov r9d, 0x50030 -> MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST
        rt.asm.mov(r9d, 0x00050030u32).unwrap();
        // call rax
        rt.asm.call(rax).unwrap();

        lock::release_global(rt);

        // mov rcx, [...]; call ...
        rt.resolve(ImportDef::NtTerminateProcess);
        // mov rcx, -0x1
        rt.asm.mov(rcx, -0x1i64).unwrap();
        // mov edx, 0xC0000001 -> STATUS_UNSUCCESSFUL
        rt.asm.mov(edx, 0xC0000001u32).unwrap();
        // call rax
        rt.asm.call(rax).unwrap();
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        rt.asm.add(rsp, 0x28).unwrap();

        // pop r14
        rt.asm.pop(r14).unwrap();
        // pop r13
        rt.asm.pop(r13).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
