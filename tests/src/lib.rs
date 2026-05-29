#[cfg(test)]
mod tests {
    use std::{ffi::c_void, mem, ptr, sync::OnceLock, thread};

    use iced_x86::{
        code_asm::{ecx, esi, ptr, qword_ptr, rax, rcx, rdi, rdx, rsi},
        Code, Instruction, MemoryOperand, Register,
    };
    use obfuscator::protections::virtualization::crypt;
    use runtime::{
        mapper::Mappable,
        runtime::{DataDef, FnDef, Runtime},
        vm::{
            self,
            bytecode::{self, VMFlag, VMReg},
            permute,
        },
    };
    use windows::Win32::System::{
        Memory::{
            VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
        },
        Threading::{FlsAlloc, TlsAlloc},
    };

    struct Executor {
        rt: Runtime,
        mem: *mut c_void,
    }

    static TLS_STATE: OnceLock<u32> = OnceLock::new();
    static TLS_STACK: OnceLock<u32> = OnceLock::new();
    static TLS_SCRATCH: OnceLock<u32> = OnceLock::new();
    static TLS_KEY: OnceLock<u32> = OnceLock::new();
    static FLS_CLEANUP: OnceLock<u32> = OnceLock::new();

    fn initialize_tls() -> [(DataDef, u32); 5] {
        [
            (
                DataDef::VmStateTlsIndex,
                *TLS_STATE.get_or_init(|| unsafe { TlsAlloc() }),
            ),
            (
                DataDef::VmStackTlsIndex,
                *TLS_STACK.get_or_init(|| unsafe { TlsAlloc() }),
            ),
            (
                DataDef::VmScratchTlsIndex,
                *TLS_SCRATCH.get_or_init(|| unsafe { TlsAlloc() }),
            ),
            (
                DataDef::VmKeyTlsIndex,
                *TLS_KEY.get_or_init(|| unsafe { TlsAlloc() }),
            ),
            (
                DataDef::VmCleanupFlsIndex,
                *FLS_CLEANUP.get_or_init(|| unsafe { FlsAlloc(None) }),
            ),
        ]
    }

    impl Executor {
        pub const TEST_KEY_SEED: u64 = 0x1234567890ABCDEF;
        pub const TEST_KEY_MUL: u64 = 0x1234567890ABCDEF;
        pub const TEST_KEY_ADD: u64 = 0x1234567890ABCDEF;

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

            // Set the native entry to point to a value different than the virtual branch for the dispatcher:
            // mov [rcx + ...], -0x1
            self.rt
                .asm
                .mov(
                    qword_ptr(rcx + self.rt.mapper.index(VMReg::NEntry) * 8),
                    -0x1,
                )
                .unwrap();

            // lea rdx, [...]
            self.rt
                .asm
                .lea(rdx, ptr(self.rt.data_labels[&DataDef::VmCode]))
                .unwrap();
            // call ...
            vm::utils::stack::call(&mut self.rt, dispatch);

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

            let mut code = self.rt.assemble(ip);

            for (def, value) in initialize_tls() {
                let offset = (self.rt.lookup(self.rt.data_labels[&def]) - ip) as usize;
                code[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            }

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
        crypt::encrypt(
            bytecode,
            Executor::TEST_KEY_SEED,
            Executor::TEST_KEY_MUL,
            Executor::TEST_KEY_ADD,
            0,
            &mut rand::thread_rng(),
        );
    }

    fn decrypt(block: &mut Vec<u8>) {
        crypt::decrypt(
            block,
            Executor::TEST_KEY_SEED,
            Executor::TEST_KEY_MUL,
            Executor::TEST_KEY_ADD,
            0,
        )
    }

    fn template(
        instructions: &[Instruction],
        setup: &[(VMReg, u64)],
        target: VMReg,
        expected: u64,
    ) {
        let mut executor = Executor::new();

        let lifted = bytecode::lift(&instructions).unwrap();
        let mut operations = permute::permute(lifted);
        let mut bytecode = bytecode::assemble(&mut executor.rt.mapper, &mut operations);

        encrypt(&mut bytecode);

        let state = executor.run(&setup, &bytecode);

        assert_eq!(
            state[(executor.rt.mapper.index(target)) as usize],
            expected,
            "{:?} | Expected: {:?}=0x{:X}, Got: {:?}=0x{:X}",
            instructions[0].code(),
            target,
            expected,
            target,
            state[(executor.rt.mapper.index(target)) as usize],
        );
    }

    fn flag(f: VMFlag) -> u64 {
        1 << (f as u64)
    }

    #[test]
    fn test_crypt() {
        let mut buffer = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];

        let before = buffer.clone();

        encrypt(&mut buffer);

        decrypt(&mut buffer);

        let after = buffer.clone();

        assert_eq!(before, after);
    }

    #[test]
    fn test_mov() {
        let mut buffer = [0u64; 4];
        let memory = buffer.as_mut_ptr() as u64;

        template(
            &[Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0x1111_1111).unwrap()],
            &[],
            VMReg::Rax,
            0x1111_1111,
        );
        template(
            &[
                Instruction::with2(
                    Code::Mov_rm64_imm32,
                    MemoryOperand::with_base(Register::RBX),
                    0x1111_1111,
                )
                .unwrap(),
                Instruction::with2(
                    Code::Mov_r32_rm32,
                    Register::EAX,
                    MemoryOperand::with_base(Register::RBX),
                )
                .unwrap(),
            ],
            &[(VMReg::Rbx, memory)],
            VMReg::Rax,
            0x1111_1111,
        );
        template(
            &[
                Instruction::with2(
                    Code::Mov_rm32_r32,
                    MemoryOperand::with_base(Register::RBX),
                    Register::EAX,
                )
                .unwrap(),
                Instruction::with2(
                    Code::Mov_r32_rm32,
                    Register::ECX,
                    MemoryOperand::with_base(Register::RBX),
                )
                .unwrap(),
            ],
            &[(VMReg::Rbx, memory), (VMReg::Rax, 0x1111_1111)],
            VMReg::Rcx,
            0x1111_1111,
        );
        template(
            &[
                Instruction::with2(
                    Code::Mov_rm16_imm16,
                    MemoryOperand::with_base(Register::RBX),
                    0x1111,
                )
                .unwrap(),
                Instruction::with2(
                    Code::Mov_r16_rm16,
                    Register::CX,
                    MemoryOperand::with_base(Register::RBX),
                )
                .unwrap(),
            ],
            &[(VMReg::Rbx, memory)],
            VMReg::Rcx,
            0x1111,
        );
        template(
            &[Instruction::with2(Code::Mov_r8_imm8, Register::AL, 0x11).unwrap()],
            &[],
            VMReg::Rax,
            0x11,
        );
    }

    #[test]
    fn test_jcc() {
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with_branch(Code::Je_rel8_64, 0x1111_1111).unwrap(),
            ],
            &[(VMReg::Rax, 0x1111_1111)],
            VMReg::NBranch,
            0x1111_1111,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with_branch(Code::Jne_rel8_64, 0x1111_1111).unwrap(),
            ],
            &[(VMReg::Rax, 0x2222_2222)],
            VMReg::NBranch,
            0x1111_1111,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with_branch(Code::Ja_rel8_64, 0x1111_1111).unwrap(),
            ],
            &[(VMReg::Rax, 0x2222_2222)],
            VMReg::NBranch,
            0x1111_1111,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x2222_2222).unwrap(),
                Instruction::with_branch(Code::Jae_rel8_64, 0x1111_1111).unwrap(),
            ],
            &[(VMReg::Rax, 0x1111_1111)],
            VMReg::NBranch,
            0,
        );
    }

    #[test]
    fn test_jmp() {
        let mut buffer = [0u64; 8];
        let memory = buffer.as_mut_ptr() as u64;

        template(
            &[Instruction::with1(Code::Jmp_rm64, Register::RAX).unwrap()],
            &[(VMReg::Rax, 0x1111_1111)],
            VMReg::NBranch,
            0x1111_1111,
        );
        template(
            &[Instruction::with_branch(Code::Jmp_rel32_64, 0x1111_1111).unwrap()],
            &[(VMReg::VImage, 0x1000_0000)],
            VMReg::NBranch,
            0x2111_1111,
        );
        template(
            &[
                Instruction::with2(
                    Code::Mov_rm64_imm32,
                    MemoryOperand::with_base(Register::RAX),
                    0x1111_1111,
                )
                .unwrap(),
                Instruction::with1(Code::Jmp_rm64, MemoryOperand::with_base(Register::RAX))
                    .unwrap(),
            ],
            &[(VMReg::Rax, memory)],
            VMReg::NBranch,
            0x1111_1111,
        );
    }

    #[test]
    fn test_lea() {
        template(
            &[Instruction::with2(
                Code::Lea_r64_m,
                Register::RAX,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::RBX,
                    Register::RCX,
                    1,
                    0x1111_1111,
                    8,
                ),
            )
            .unwrap()],
            &[(VMReg::Rbx, 0x1111_1111), (VMReg::Rcx, 0x1111_1111)],
            VMReg::Rax,
            0x3333_3333,
        );
        template(
            &[Instruction::with2(
                Code::Lea_r32_m,
                Register::EAX,
                MemoryOperand::with_base_index_scale_displ_size(
                    Register::RBX,
                    Register::RCX,
                    1,
                    0x1111_1111,
                    4,
                ),
            )
            .unwrap()],
            &[(VMReg::Rbx, 0x1111_1111), (VMReg::Rcx, 0x1111_1111)],
            VMReg::Rax,
            0x3333_3333,
        );
    }

    #[test]
    fn test_add() {
        template(
            &[Instruction::with2(Code::Add_r64_rm64, Register::RAX, Register::RBX).unwrap()],
            &[(VMReg::Rax, 0x1111_1111), (VMReg::Rbx, 0x1111_1111)],
            VMReg::Rax,
            0x2222_2222,
        );
        template(
            &[Instruction::with2(Code::Add_rm32_imm32, Register::EAX, 0x1111_1111).unwrap()],
            &[(VMReg::Rax, 0x1111_1111)],
            VMReg::Rax,
            0x2222_2222,
        );
        template(
            &[Instruction::with2(Code::Add_rm16_imm16, Register::AX, 0x1111).unwrap()],
            &[(VMReg::Rax, 0x1111)],
            VMReg::Rax,
            0x2222,
        );
        template(
            &[Instruction::with2(Code::Add_rm8_imm8, Register::AL, 0x11).unwrap()],
            &[(VMReg::Rax, 0x11)],
            VMReg::Rax,
            0x22,
        );
    }

    #[test]
    fn test_sub() {
        template(
            &[Instruction::with2(Code::Sub_r64_rm64, Register::RAX, Register::RBX).unwrap()],
            &[(VMReg::Rax, 0x2222_2222), (VMReg::Rbx, 0x1111_1111)],
            VMReg::Rax,
            0x1111_1111,
        );
        template(
            &[Instruction::with2(Code::Sub_rm32_imm32, Register::EAX, 0x1111_1111).unwrap()],
            &[(VMReg::Rax, 0x2222_2222)],
            VMReg::Rax,
            0x1111_1111,
        );
        template(
            &[Instruction::with2(Code::Sub_rm16_imm16, Register::AX, 0x1111).unwrap()],
            &[(VMReg::Rax, 0x2222)],
            VMReg::Rax,
            0x1111,
        );
        template(
            &[Instruction::with2(Code::Sub_rm8_imm8, Register::AL, 0x11).unwrap()],
            &[(VMReg::Rax, 0x22)],
            VMReg::Rax,
            0x11,
        );
    }

    #[test]
    fn test_cmp() {
        template(
            &[
                Instruction::with2(Code::Cmp_r64_rm64, Register::RAX, Register::RBX).unwrap(),
                Instruction::with_branch(Code::Je_rel8_64, 0x1111_1111).unwrap(),
            ],
            &[(VMReg::Rax, 0x1111_1111), (VMReg::Rbx, 0x1111_1111)],
            VMReg::NBranch,
            0x1111_1111,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_r32_rm32, Register::EAX, Register::EBX).unwrap(),
                Instruction::with_branch(Code::Je_rel8_64, 0x1111_1111).unwrap(),
            ],
            &[(VMReg::Rax, 0x1111_1111), (VMReg::Rbx, 0x1111_1111)],
            VMReg::NBranch,
            0x1111_1111,
        );
    }

    #[test]
    fn test_cmov() {
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with2(Code::Cmove_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x1111_1111),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x1111_1111,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with2(Code::Cmove_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x2222_2222),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x2222_2222,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with2(Code::Cmovne_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x2222_2222),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x1111_1111,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with2(Code::Cmovne_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x1111_1111),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x2222_2222,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with2(Code::Cmova_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x2222_2222),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x1111_1111,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with2(Code::Cmova_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x1111_1111),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x2222_2222,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with2(Code::Cmovae_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x2222_2222),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x1111_1111,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x2222_2222).unwrap(),
                Instruction::with2(Code::Cmovae_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x1111_1111),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x2222_2222,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x2222_2222).unwrap(),
                Instruction::with2(Code::Cmovb_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x1111_1111),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x1111_1111,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with2(Code::Cmovb_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x2222_2222),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x2222_2222,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with2(Code::Cmovbe_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x1111_1111),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x1111_1111,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with2(Code::Cmovbe_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x2222_2222),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x2222_2222,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with2(Code::Cmovg_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x2222_2222),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x1111_1111,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with2(Code::Cmovg_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x1111_1111),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x2222_2222,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with2(Code::Cmovge_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x2222_2222),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x1111_1111,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x2222_2222).unwrap(),
                Instruction::with2(Code::Cmovge_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x1111_1111),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x2222_2222,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x2222_2222).unwrap(),
                Instruction::with2(Code::Cmovl_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x1111_1111),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x1111_1111,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with2(Code::Cmovl_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x2222_2222),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x2222_2222,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with2(Code::Cmovle_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x1111_1111),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x1111_1111,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with2(Code::Cmovle_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x2222_2222),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x2222_2222,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, -0x1).unwrap(),
                Instruction::with2(Code::Cmovo_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x7FFF_FFFF_FFFF_FFFF),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x1111_1111,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with2(Code::Cmovo_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x1111_1111),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x2222_2222,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with2(Code::Cmovno_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x1111_1111),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x1111_1111,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, -0x1).unwrap(),
                Instruction::with2(Code::Cmovno_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x7FFF_FFFF_FFFF_FFFF),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x2222_2222,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with2(Code::Cmovp_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x1111_1111),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x1111_1111,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x2222_2222).unwrap(),
                Instruction::with2(Code::Cmovp_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x1111_1111),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x2222_2222,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x2222_2222).unwrap(),
                Instruction::with2(Code::Cmovnp_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x1111_1111),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x1111_1111,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with2(Code::Cmovnp_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x1111_1111),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x2222_2222,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x2222_2222).unwrap(),
                Instruction::with2(Code::Cmovs_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x1111_1111),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x1111_1111,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with2(Code::Cmovs_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x2222_2222),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x2222_2222,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x1111_1111).unwrap(),
                Instruction::with2(Code::Cmovns_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x2222_2222),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x1111_1111,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm32, Register::RAX, 0x2222_2222).unwrap(),
                Instruction::with2(Code::Cmovns_r64_rm64, Register::RBX, Register::RCX).unwrap(),
            ],
            &[
                (VMReg::Rax, 0x1111_1111),
                (VMReg::Rbx, 0x2222_2222),
                (VMReg::Rcx, 0x1111_1111),
            ],
            VMReg::Rbx,
            0x2222_2222,
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
}
