#[cfg(test)]
mod tests {
    use std::{ffi::c_void, mem, ptr, sync::OnceLock, thread};

    use iced_x86::{
        code_asm::{ecx, esi, ptr, rax, rcx, rdi, rdx, rsi},
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
    static TLS_KEY: OnceLock<u32> = OnceLock::new();
    static FLS_CLEANUP: OnceLock<u32> = OnceLock::new();

    fn initialize_tls() -> [(DataDef, u32); 3] {
        [
            (
                DataDef::VmStateTlsIndex,
                *TLS_STATE.get_or_init(|| unsafe { TlsAlloc() }),
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
        let operations = permute::permute(lifted);
        let mut bytecode = bytecode::assemble(&mut executor.rt.mapper, &operations);

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

    macro_rules! instruction {
        (branch $code:ident, $target:expr) => {
            Instruction::with_branch(Code::$code, $target).unwrap()
        };
        ($code:ident, $a:expr) => {
            Instruction::with1(Code::$code, $a).unwrap()
        };
        ($code:ident, $a:expr, $b:expr) => {
            Instruction::with2(Code::$code, $a, $b).unwrap()
        };
    }

    macro_rules! case {
        ([$($i:expr),* $(,)?], [$($r:ident = $v:expr),* $(,)?], $t:ident => $e:expr) => {
            template(
                &[$($i),*],
                &[$((VMReg::$r, $v)),*],
                VMReg::$t,
                $e,
            );
        };
    }

    macro_rules! binary {
        ($name:ident, $op:ident,
            ($a64:expr, $b64:expr => $r64:expr),
            ($a32:expr, $i32:expr => $r32:expr),
            ($a16:expr, $i16:expr => $r16:expr),
            ($a8:expr,  $i8:expr  => $r8:expr) $(,)?
        ) => {
            #[test]
            fn $name() {
                paste::paste! {
                    case!([instruction!([<$op _r64_rm64>], Register::RAX, Register::RBX)],
                          [Rax = $a64, Rbx = $b64], Rax => $r64);
                    case!([instruction!([<$op _rm32_imm32>], Register::EAX, $i32)],
                          [Rax = $a32], Rax => $r32);
                    case!([instruction!([<$op _rm16_imm16>], Register::AX, $i16)],
                          [Rax = $a16], Rax => $r16);
                    case!([instruction!([<$op _rm8_imm8>], Register::AL, $i8)],
                          [Rax = $a8], Rax => $r8);
                }
            }
        };
    }

    macro_rules! cmov_case {
        ($cmov:ident, $cmp:expr, $rax:expr, $expected:expr) => {
            case!(
                [
                    instruction!(Cmp_rm64_imm32, Register::RAX, $cmp),
                    instruction!($cmov, Register::RBX, Register::RCX),
                ],
                [Rax = $rax, Rbx = 0x2222_2222, Rcx = 0x1111_1111],
                Rbx => $expected
            );
        };
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
        case!([instruction!(Mov_r64_imm64, Register::RAX, 0x1111_1111_1111_1111u64)],
              [], Rax => 0x1111_1111_1111_1111);
        case!([instruction!(Mov_r32_imm32, Register::EAX, 0x1111_1111)],
              [], Rax => 0x1111_1111);
        case!([instruction!(Mov_r16_imm16, Register::AX, 0x1111)],
              [], Rax => 0x1111);
        case!([instruction!(Mov_r8_imm8, Register::AL, 0x11)],
              [], Rax => 0x11);
    }

    #[test]
    fn test_jcc() {
        case!([instruction!(Cmp_rm64_imm32, Register::RAX, 0x1111_1111),
               instruction!(branch Je_rel8_64, 0x1111_1111)],
              [Rax = 0x1111_1111], NBranch => 0x1111_1111);
        case!([instruction!(Cmp_rm64_imm32, Register::RAX, 0x1111_1111),
               instruction!(branch Jne_rel8_64, 0x1111_1111)],
              [Rax = 0x2222_2222], NBranch => 0x1111_1111);
        case!([instruction!(Cmp_rm64_imm32, Register::RAX, 0x1111_1111),
               instruction!(branch Ja_rel8_64, 0x1111_1111)],
              [Rax = 0x2222_2222], NBranch => 0x1111_1111);
        case!([instruction!(Cmp_rm64_imm32, Register::RAX, 0x1111_1111),
               instruction!(branch Jae_rel8_64, 0x1111_1111)],
              [Rax = 0x2222_2222], NBranch => 0x1111_1111);
    }

    #[test]
    fn test_jmp() {
        case!([instruction!(Jmp_rm64, Register::RAX)],
              [Rax = 0x1111_1111], NBranch => 0x1111_1111);
        case!([instruction!(Jmp_rm64, Register::RBX)],
              [Rbx = 0x1111_1111], NBranch => 0x1111_1111);
        case!([instruction!(branch Jmp_rel8_64, 0x1111_1111)],
              [VImage = 0x1000_0000], NBranch => 0x2111_1111);
        case!([instruction!(branch Jmp_rel32_64, 0x1111_1111)],
              [VImage = 0x1000_0000], NBranch => 0x2111_1111);
    }

    #[test]
    fn test_lea() {
        case!([instruction!(Lea_r64_m, Register::RAX,
                  MemoryOperand::with_base_displ_size(Register::RBX, 0x1111_1111, 8))],
              [Rbx = 0x1111_1111], Rax => 0x2222_2222);
        case!([instruction!(Lea_r32_m, Register::EAX,
                  MemoryOperand::with_base_displ_size(Register::RBX, 0x1111_1111, 4))],
              [Rbx = 0x1111_1111], Rax => 0x2222_2222);
        case!([instruction!(Lea_r16_m, Register::AX,
                  MemoryOperand::with_base_displ_size(Register::RBX, 0x1111, 2))],
              [Rbx = 0x1111], Rax => 0x2222);
        case!([instruction!(Lea_r16_m, Register::AX,
                  MemoryOperand::with_base_displ_size(Register::RBX, 0x11, 2))],
              [Rbx = 0x11], Rax => 0x22);
    }

    binary!(
        test_add, Add,
        (0x1111_1111, 0x1111_1111 => 0x2222_2222),
        (0x1111_1111, 0x1111_1111 => 0x2222_2222),
        (0x1111, 0x1111 => 0x2222),
        (0x11, 0x11 => 0x22),
    );

    binary!(
        test_sub, Sub,
        (0x2222_2222, 0x1111_1111 => 0x1111_1111),
        (0x2222_2222, 0x1111_1111 => 0x1111_1111),
        (0x2222, 0x1111 => 0x1111),
        (0x22, 0x11 => 0x11),
    );

    #[test]
    fn test_cmp() {
        case!([instruction!(Cmp_rm64_imm32, Register::RAX, 0x1111_1111),
               instruction!(branch Je_rel8_64, 0x1111_1111)],
              [Rax = 0x1111_1111], NBranch => 0x1111_1111);
        case!([instruction!(Cmp_rm32_imm32, Register::EAX, 0x1111_1111),
               instruction!(branch Je_rel8_64, 0x1111_1111)],
              [Rax = 0x1111_1111], NBranch => 0x1111_1111);
        case!([instruction!(Cmp_rm16_imm16, Register::AX, 0x1111),
               instruction!(branch Je_rel8_64, 0x1111_1111)],
              [Rax = 0x1111], NBranch => 0x1111_1111);
        case!([instruction!(Cmp_rm8_imm8, Register::AL, 0x11),
               instruction!(branch Je_rel8_64, 0x1111_1111)],
              [Rax = 0x11], NBranch => 0x1111_1111);
    }

    binary!(
        test_and, And,
        (0xFF00_FF00, 0x0FF0_0FF0 => 0x0F00_0F00),
        (0xFF00_FF00, 0x0FF0_0FF0 => 0x0F00_0F00),
        (0xFF00, 0x0FF0 => 0x0F00),
        (0xFF, 0x0F => 0x0F),
    );

    binary!(
        test_or, Or,
        (0xFF00_0000, 0x0000_00FF => 0xFF00_00FF),
        (0xFF00_0000, 0x0000_00FF => 0xFF00_00FF),
        (0xFF00, 0x00FF => 0xFFFF),
        (0xF0, 0x0F => 0xFF),
    );

    binary!(
        test_xor, Xor,
        (0xFFFF_FFFF, 0x0F0F_0F0F => 0xF0F0_F0F0),
        (0xFFFF_FFFF, 0x0F0F_0F0F => 0xF0F0_F0F0),
        (0xFFFF, 0x0F0F => 0xF0F0),
        (0xFF, 0x0F => 0xF0),
    );

    #[test]
    fn test_test() {
        case!([instruction!(Test_rm64_imm32, Register::RAX, 0x00FF),
               instruction!(branch Je_rel8_64, 0x1111_1111)],
              [Rax = 0xFF00], NBranch => 0x1111_1111);
        case!([instruction!(Test_rm32_imm32, Register::EAX, 0x00FF),
               instruction!(branch Je_rel8_64, 0x1111_1111)],
              [Rax = 0xFF00], NBranch => 0x1111_1111);
        case!([instruction!(Test_rm16_imm16, Register::AX, 0x00FF),
               instruction!(branch Je_rel8_64, 0x1111_1111)],
              [Rax = 0xFF00], NBranch => 0x1111_1111);
        case!([instruction!(Test_rm8_imm8, Register::AL, 0x0F),
               instruction!(branch Je_rel8_64, 0x1111_1111)],
              [Rax = 0xF0], NBranch => 0x1111_1111);
    }

    #[test]
    fn test_cmov() {
        cmov_case!(Cmove_r64_rm64,  0x1111_1111, 0x1111_1111, 0x1111_1111);
        cmov_case!(Cmovne_r64_rm64, 0x1111_1111, 0x2222_2222, 0x1111_1111);
        cmov_case!(Cmova_r64_rm64,  0x1111_1111, 0x2222_2222, 0x1111_1111);
        cmov_case!(Cmovae_r64_rm64, 0x1111_1111, 0x2222_2222, 0x1111_1111);
    }

    #[test]
    fn test_flags() {
        // PF
        case!([instruction!(Add_rm64_imm8, Register::RAX, 0x1)],
              [Rax = 0x2],
              Flags => flag(VMFlag::Parity));
        // SF & PF
        case!([instruction!(Add_rm64_imm8, Register::RAX, -0x1)],
              [Rax = 0x0],
              Flags => flag(VMFlag::Sign) | flag(VMFlag::Parity));
        // OF & SF & AF & PF
        case!([instruction!(Add_rm64_imm8, Register::RAX, 0x1)],
              [Rax = 0x7FFF_FFFF_FFFF_FFFF],
              Flags => flag(VMFlag::Overflow) | flag(VMFlag::Sign)
                     | flag(VMFlag::Auxiliary) | flag(VMFlag::Parity));
        // ZF & CF & AF & PF
        case!([instruction!(Add_rm64_imm8, Register::RAX, 0x1)],
              [Rax = 0xFFFF_FFFF_FFFF_FFFF],
              Flags => flag(VMFlag::Carry) | flag(VMFlag::Parity)
                     | flag(VMFlag::Auxiliary) | flag(VMFlag::Zero));
    }
}
