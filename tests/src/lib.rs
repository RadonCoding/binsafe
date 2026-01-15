#[cfg(test)]
mod tests {
    use std::{ffi::c_void, mem, ptr, thread};

    use iced_x86::{
        code_asm::{ecx, esi, ptr, rax, rcx, rdi, rdx, rsi},
        Code, Instruction, MemoryOperand, Register,
    };
    use runtime::{
        mapper::Mappable,
        runtime::{DataDef, FnDef, Runtime},
        vm::{
            bytecode::{self, VMFlag, VMReg},
            stack,
        },
    };
    use windows::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    };

    struct Executor {
        rt: Runtime,
        mem: *mut c_void,
    }

    impl Executor {
        pub const TEST_KEY_SEED: u64 = 0x1234567890ABCDEF;
        pub const TEST_KEY_MUL: u64 = 0xFEDCBA0987654321;
        pub const TEST_KEY_ADD: u64 = 0x0123456789ABCDEF;

        pub const TEST_VSK: u8 = 0x4C;

        pub const SIZE: usize = 0x10000;

        fn new() -> Self {
            let mut rt = Runtime::new(64);

            rt.define_data_qword(DataDef::VmKeySeed, Self::TEST_KEY_SEED);
            rt.define_data_qword(DataDef::VmKeyMul, Self::TEST_KEY_MUL);
            rt.define_data_qword(DataDef::VmKeyAdd, Self::TEST_KEY_ADD);

            let mem = unsafe {
                VirtualAlloc(
                    None,
                    Self::SIZE,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )
            };

            Self { rt, mem }
        }

        fn run(&mut self, setup: &[(VMReg, u64)], bytecode: &[u8]) -> [u64; VMReg::COUNT] {
            let dispatch = self.rt.func_labels[&FnDef::VmDispatch];

            // call ...
            self.rt
                .asm
                .call(self.rt.func_labels[&FnDef::VmGInit])
                .unwrap();
            // call ...
            self.rt
                .asm
                .call(self.rt.func_labels[&FnDef::VmTInit])
                .unwrap();

            // call ...
            self.rt
                .asm
                .call(self.rt.func_labels[&FnDef::VmHandlersInitialize])
                .unwrap();

            // mov ecx, [...]
            self.rt
                .asm
                .mov(ecx, ptr(self.rt.data_labels[&DataDef::VmStateTlsIndex]))
                .unwrap();
            // mov rcx, [0x1480 + rcx*8]
            self.rt.asm.mov(rcx, ptr(0x1480 + rcx * 8).gs()).unwrap();

            for &(reg, val) in setup {
                // mov rax, ...
                self.rt.asm.mov(rax, val).unwrap();
                // mov [rcx + ...], rax
                self.rt
                    .asm
                    .mov(ptr(rcx + self.rt.mapper.index(reg) * 8), rax)
                    .unwrap();
            }

            // mov rax, ...
            self.rt
                .asm
                .mov(rax, &Self::TEST_VSK as *const u8 as u64)
                .unwrap();
            // mov [rcx + ...], rax
            self.rt
                .asm
                .mov(ptr(rcx + self.rt.mapper.index(VMReg::Vsk) * 8), rax)
                .unwrap();

            // lea rdx, [...]
            self.rt
                .asm
                .lea(rdx, ptr(self.rt.data_labels[&DataDef::VmCode]))
                .unwrap();
            // call ...
            stack::call(&mut self.rt, dispatch);

            let mut state = [0u64; VMReg::COUNT];

            // mov esi, [...]
            self.rt
                .asm
                .mov(esi, ptr(self.rt.data_labels[&DataDef::VmStateTlsIndex]))
                .unwrap();
            // mov rsi, [0x1480 + rsi*8]
            self.rt.asm.mov(rsi, ptr(0x1480 + rsi * 8).gs()).unwrap();
            // mov rdi, ...
            self.rt.asm.mov(rdi, state.as_mut_ptr() as u64).unwrap();
            // mov rcx, ...
            self.rt.asm.mov(rcx, VMReg::COUNT as u64).unwrap();
            // rep movsq
            self.rt.asm.rep().movsq().unwrap();

            // ret
            self.rt.asm.ret().unwrap();

            self.rt.define_data_bytes(DataDef::VmCode, bytecode);

            let ip = self.mem as u64;

            let code = self.rt.assemble(ip);

            assert!(code.len() <= Self::SIZE);

            unsafe {
                ptr::copy_nonoverlapping(code.as_ptr(), self.mem as *mut u8, code.len());
            }

            let entry_point = unsafe { mem::transmute::<*mut c_void, extern "C" fn()>(self.mem) };

            let handle = thread::spawn(move || entry_point());

            handle.join().unwrap();

            state
        }
    }

    impl Drop for Executor {
        fn drop(&mut self) {
            unsafe {
                let _ = VirtualFree(self.mem, 0, MEM_RELEASE);
            }
        }
    }

    fn encrypt(bytecode: &mut Vec<u8>) {
        let mut key = Executor::TEST_KEY_SEED;

        let length = TryInto::<u16>::try_into(bytecode.len()).unwrap();

        while bytecode.len() % 8 != 0 {
            bytecode.push(0);
        }

        for chunk in bytecode.chunks_exact_mut(8) {
            let mut qword = u64::from_le_bytes(chunk.try_into().unwrap());
            qword ^= key;
            chunk.copy_from_slice(&qword.to_le_bytes());

            key ^= (qword ^ (Executor::TEST_VSK as u64)) as u64;
            key = key
                .wrapping_mul(Executor::TEST_KEY_MUL)
                .wrapping_add(Executor::TEST_KEY_ADD);
        }

        bytecode.splice(0..0, length.to_le_bytes());
        bytecode.push(0);
    }

    fn decrypt(block: &mut Vec<u8>) -> Vec<u8> {
        let mut key = Executor::TEST_KEY_SEED;

        let length =
            u16::from_le_bytes(block.drain(0..2).collect::<Vec<u8>>().try_into().unwrap()) as usize;

        block.pop();

        for chunk in block.chunks_exact_mut(8) {
            let qword = u64::from_le_bytes(chunk.try_into().unwrap());
            let original = qword ^ key;
            chunk.copy_from_slice(&original.to_le_bytes());

            key ^= (qword ^ (Executor::TEST_VSK as u64)) as u64;
            key = key
                .wrapping_mul(Executor::TEST_KEY_MUL)
                .wrapping_add(Executor::TEST_KEY_ADD);
        }

        block.truncate(length);
        block.clone()
    }

    fn template(
        instructions: &[Instruction],
        setup: &[(VMReg, u64)],
        target: VMReg,
        expected: u64,
    ) {
        let mut executor = Executor::new();

        let mut bytecode = bytecode::convert(&mut executor.rt.mapper, &instructions).unwrap();

        encrypt(&mut bytecode);

        let state = executor.run(&setup, &bytecode);

        let mut dump = Vec::new();

        for reg in VMReg::VARIANTS {
            dump.push(format!(
                "{:?}=0x{:X}",
                reg,
                state[executor.rt.mapper.index(*reg) as usize]
            ));
        }

        assert_eq!(
            state[(executor.rt.mapper.index(target)) as usize],
            expected,
            "{:?} | Expected: 0x{:X}, Got: 0x{:X}\n{}",
            instructions[0].code(),
            expected,
            state[(executor.rt.mapper.index(target)) as usize],
            dump.join("\n")
        );
    }

    fn flag(f: VMFlag) -> u64 {
        1 << (f as u64)
    }

    #[test]
    fn test_crypt() {
        let mut buffer = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];

        let original = buffer.clone();

        encrypt(&mut buffer);

        let result = decrypt(&mut buffer);

        assert_eq!(original, result);
    }

    #[test]
    fn test_mov_reg_imm() {
        template(
            &[Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0x0000_0000).unwrap()],
            &[(VMReg::Rax, 0xFFFF_FFFF_FFFF_FFFF)],
            VMReg::Rax,
            0x0000_0000_0000_0000,
        );
    }

    #[test]
    fn test_flags() {
        // SF & PF
        template(
            &[Instruction::with2(Code::Add_rm64_imm8, Register::RAX, -0x1).unwrap()],
            &[(VMReg::Rax, 0x0)],
            VMReg::Flags,
            flag(VMFlag::Sign) | flag(VMFlag::Parity),
        );
        // OF & SF & AF & PF
        template(
            &[Instruction::with2(Code::Add_rm64_imm8, Register::RAX, 0x1).unwrap()],
            &[(VMReg::Rax, 0x7FFF_FFFF_FFFF_FFFF)],
            VMReg::Flags,
            flag(VMFlag::Overflow)
                | flag(VMFlag::Sign)
                | flag(VMFlag::Auxiliary)
                | flag(VMFlag::Parity),
        );
        // ZF & CF & AF & PF
        template(
            &[Instruction::with2(Code::Add_rm64_imm8, Register::RAX, 0x1).unwrap()],
            &[(VMReg::Rax, 0xFFFF_FFFF_FFFF_FFFF)],
            VMReg::Flags,
            flag(VMFlag::Carry)
                | flag(VMFlag::Parity)
                | flag(VMFlag::Auxiliary)
                | flag(VMFlag::Zero),
        );
    }

    #[test]
    fn test_jcc() {
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm8, Register::RAX, 0x1).unwrap(),
                Instruction::with_branch(Code::Je_rel8_64, 0xDEAD).unwrap(),
            ],
            &[(VMReg::Rax, 0x1)],
            VMReg::Vra,
            0xDEAD,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm8, Register::RAX, 0x2).unwrap(),
                Instruction::with_branch(Code::Jne_rel8_64, 0xDEAD).unwrap(),
            ],
            &[(VMReg::Rax, 0x1)],
            VMReg::Vra,
            0xDEAD,
        );
    }

    #[test]
    fn test_memory_load_store() {
        let mut buffer = [0u64; 2];

        let memory = buffer.as_mut_ptr() as u64;

        template(
            &[
                Instruction::with2(
                    Code::Mov_rm64_r64,
                    MemoryOperand::with_base_index_scale_displ_size(
                        Register::RBX,
                        Register::None,
                        1,
                        0,
                        8,
                    ),
                    Register::RAX,
                )
                .unwrap(),
                Instruction::with2(
                    Code::Mov_r64_rm64,
                    Register::RCX,
                    MemoryOperand::with_base_index_scale_displ_size(
                        Register::RBX,
                        Register::None,
                        1,
                        0,
                        8,
                    ),
                )
                .unwrap(),
            ],
            &[(VMReg::Rax, 0xDEADC0DE), (VMReg::Rbx, memory)],
            VMReg::Rcx,
            0xDEADC0DE,
        );
    }

    #[test]
    fn test_push_pop() {
        let mut stack = [0u64; 2];

        let sp = unsafe { stack.as_mut_ptr().add(stack.len()) } as u64;

        template(
            &[
                Instruction::with1(Code::Push_r64, Register::RAX).unwrap(),
                Instruction::with1(Code::Push_r64, Register::RBX).unwrap(),
                Instruction::with1(Code::Pop_r64, Register::RBX).unwrap(),
                Instruction::with1(Code::Pop_r64, Register::RAX).unwrap(),
            ],
            &[(VMReg::Rsp, sp), (VMReg::Rax, 0x1111), (VMReg::Rbx, 0x2222)],
            VMReg::Rax,
            0x1111,
        );
    }

    #[test]
    fn test_lea_sib() {
        template(
            &[Instruction::with2(
                Code::Lea_r64_m,
                Register::RAX,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::RBX,
                    Register::RCX,
                    4,
                    0x8,
                    8,
                ),
            )
            .unwrap()],
            &[(VMReg::Rbx, 0x1000), (VMReg::Rcx, 0x10)],
            VMReg::Rax,
            0x1000 + (0x10 * 4) + 0x8,
        );
    }
}
