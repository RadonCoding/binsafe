use iced_x86::code_asm::{
    byte_ptr, dword_ptr, eax, ptr, r12, r13, r14, r8, r8d, r9, rax, rcx, rdx, CodeLabel,
};

use crate::{
    runtime::{FnDef, Runtime},
    vm::{
        bytecode::{VMOp, VMReg},
        utils::{self},
    },
    VM_DISPATCH_SIZE, VM_TRAMPOLINE_SIZE,
};

const HANDLERS: [(VMOp, FnDef); 45] = [
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
    (VMOp::AddCarry, FnDef::VmHandlerAddCarry),
    (VMOp::SubBorrow, FnDef::VmHandlerSubBorrow),
    (VMOp::Exchange, FnDef::VmHandlerExchange),
    (VMOp::ExchangeAdd, FnDef::VmHandlerExchangeAdd),
    (VMOp::CompareExchange, FnDef::VmHandlerCompareExchange),
    (VMOp::And, FnDef::VmHandlerAnd),
    (VMOp::Or, FnDef::VmHandlerOr),
    (VMOp::Xor, FnDef::VmHandlerXor),
    (VMOp::Test, FnDef::VmHandlerTest),
    (VMOp::Rol, FnDef::VmHandlerRol),
    (VMOp::Ror, FnDef::VmHandlerRor),
    (VMOp::Shl, FnDef::VmHandlerShl),
    (VMOp::Shr, FnDef::VmHandlerShr),
    (VMOp::Sar, FnDef::VmHandlerSar),
    (VMOp::Mul, FnDef::VmHandlerMul),
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
    (VMOp::VectorOr, FnDef::VmHandlerVectorOr),
    (VMOp::VectorXor, FnDef::VmHandlerVectorXor),
    (VMOp::VectorAndNot, FnDef::VmHandlerVectorAndNot),
    (VMOp::Divide, FnDef::VmHandlerDivide),
];

// void (unsigned char*)
pub fn build(rt: &mut Runtime) {
    let mut setup_block = rt.asm.create_label();
    let mut start_block = rt.asm.create_label();
    let mut execute_loop = rt.asm.create_label();
    let mut check_loop = rt.asm.create_label();
    let mut check_exit = rt.asm.create_label();
    let mut resolved = rt.asm.create_label();
    let mut epilogue = rt.asm.create_label();

    // push r13
    rt.asm.push(r13).unwrap();
    // push r14
    rt.asm.push(r14).unwrap();

    // mov r13, rcx
    rt.asm.mov(r13, rcx).unwrap();

    rt.asm.set_label(&mut setup_block).unwrap();
    {
        // Initialize block pointer and block length:
        // mov [r12 + ...], r13
        utils::vreg::store_reg(rt, r12, r13, VMReg::BPointer);
        // eax = length
        utils::bytecode::read_word_zx(rt, r13, eax);
        // mov [r12 + ...], rax
        utils::vreg::store_reg(rt, r12, rax, VMReg::BLength);

        // Store the end of the block:
        // lea r14, [r13 + rax]
        rt.asm.lea(r14, ptr(r13 + rax)).unwrap();

        // Decrypt the block:
        // mov rcx, 0x1
        rt.asm.mov(rcx, 0x1u64).unwrap();
        // call ...
        rt.asm.call(rt.function_labels[&FnDef::VmCrypt]).unwrap();
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
        // cmp [r12 + ...], 0x0
        utils::vreg::cmp_imm(rt, r12, VMReg::NBranch, 0x0);
        // je ...
        rt.asm.je(check_exit).unwrap();

        // mov rax, [r12 + ...]
        utils::vreg::load_reg(rt, r12, VMReg::NEntry, rax);
        // cmp [r12 + ...],
        utils::vreg::cmp_reg(rt, r12, VMReg::NBranch, rax);
        // jne ...
        rt.asm.jne(check_exit).unwrap();

        // If the branch points to the native entry then re-execute the block:
        // mov r13, [...]
        utils::vreg::load_reg(rt, r12, VMReg::BPointer, r13);
        // eax = length
        utils::bytecode::read_word_zx(rt, r13, eax);
        // mov [r12 + ...], rax
        utils::vreg::store_reg(rt, r12, rax, VMReg::BLength);
        // jmp ...
        rt.asm.jmp(start_block).unwrap();
    }

    rt.asm.set_label(&mut check_exit).unwrap();
    {
        // Re-encrypt the current block:
        // xor rcx, rcx
        rt.asm.xor(rcx, rcx).unwrap();
        // call ...
        rt.asm.call(rt.function_labels[&FnDef::VmCrypt]).unwrap();

        // mov rax, [r12 + ...]
        utils::vreg::load_reg(rt, r12, VMReg::NExit, rax);
        // mov rcx, [r12 + ...]
        utils::vreg::load_reg(rt, r12, VMReg::NBranch, rcx);
        // test rcx, rcx
        rt.asm.test(rcx, rcx).unwrap();
        // cmovnz rax, rcx
        rt.asm.cmovne(rax, rcx).unwrap();
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

            // mov r8d, [rax + 0x1]
            rt.asm.mov(r8d, ptr(rax + 0x1)).unwrap();

            // add rax, ...
            rt.asm.add(rax, VM_DISPATCH_SIZE as i32).unwrap();

            // mov rdx, rax
            rt.asm.mov(rdx, rax).unwrap();
            // call ...
            rt.asm.call(rt.function_labels[&FnDef::VmLookup]).unwrap();
            // mov r13, rax
            rt.asm.mov(r13, rax).unwrap();

            // jmp ...
            rt.asm.jmp(setup_block).unwrap();
        }
    }

    rt.asm.set_label(&mut epilogue).unwrap();
    {
        // pop r14
        rt.asm.pop(r14).unwrap();
        // pop r13
        rt.asm.pop(r13).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
