#[cfg(test)]
mod tests {
    use std::{ffi::c_void, mem, ptr};

    use iced_x86::{
        code_asm::{ptr, rcx, rdx},
        Code, Instruction, MemoryOperand, Register,
    };
    use runtime::{
        mapper::MappedSpec,
        runtime::{DataDef, FnDef, Runtime},
        vm::{
            bytecode::{self, VMFlag, VMOp, VMReg},
            stack,
        },
    };
    use windows::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    };

    struct Executor {
        rt: Runtime,
        mem: *mut c_void,
        size: usize,
    }

    impl Executor {
        fn new(size: usize) -> Self {
            let rt = Runtime::new(64);
            let mem = unsafe {
                VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
            };
            Self { rt, mem, size }
        }

        fn run(&mut self, registers: &mut [u64], bytecode: &[u8]) {
            let dispatch = self.rt.func_labels[&FnDef::VmDispatch];

            // call ...
            self.rt
                .asm
                .call(self.rt.func_labels[&FnDef::InitializeStack])
                .unwrap();

            // mov rcx, ...
            self.rt.asm.mov(rcx, registers.as_mut_ptr() as u64).unwrap();
            // lea rdx, [...]
            self.rt
                .asm
                .lea(rdx, ptr(self.rt.data_labels[&DataDef::VmCode]))
                .unwrap();
            // call ...
            stack::call(&mut self.rt, dispatch);
            // ret
            self.rt.asm.ret().unwrap();

            self.rt.define_data(DataDef::VmCode, bytecode);

            let ip = self.mem as u64;

            let code = self.rt.assemble(ip);

            assert!(code.len() <= self.size);

            unsafe {
                ptr::copy_nonoverlapping(code.as_ptr(), self.mem as *mut u8, code.len());

                let entry_point: extern "C" fn() = mem::transmute(self.mem);

                entry_point();
            }
        }
    }

    impl Drop for Executor {
        fn drop(&mut self) {
            unsafe {
                let _ = VirtualFree(self.mem, 0, MEM_RELEASE);
            }
        }
    }

    fn template(
        instructions: &[Instruction],
        setup: &[(VMReg, u64)],
        target: VMReg,
        expected: u64,
    ) {
        let mut executor = Executor::new(0x2000);

        let mut registers = [0u64; VMReg::COUNT];

        for (reg, val) in setup {
            registers[(executor.rt.mapper.index(*reg)) as usize] = *val;
        }

        let mut bytecode = Vec::new();

        for instruction in instructions {
            let mut part = bytecode::convert(&mut executor.rt.mapper, 0x0, &instruction).unwrap();

            bytecode.append(&mut part);
        }

        bytecode.push(executor.rt.mapper.index(VMOp::Invalid));

        executor.run(&mut registers, &bytecode);

        assert_eq!(
            registers[(executor.rt.mapper.index(target)) as usize],
            expected,
            "Failed: {:?} | Expected: 0x{:X}, Got: 0x{:X}",
            instructions[0],
            expected,
            registers[(executor.rt.mapper.index(target)) as usize]
        );
    }

    fn flag(f: VMFlag) -> u64 {
        1 << (f as u64)
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
            VMReg::Rip,
            0xDEAD,
        );
        template(
            &[
                Instruction::with2(Code::Cmp_rm64_imm8, Register::RAX, 0x2).unwrap(),
                Instruction::with_branch(Code::Jne_rel8_64, 0xDEAD).unwrap(),
            ],
            &[(VMReg::Rax, 0x1)],
            VMReg::Rip,
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
        let mut stack = [0u64; 4];

        let sp = unsafe { stack.as_mut_ptr().add(stack.len()) } as u64;

        template(
            &[
                Instruction::with1(Code::Push_r64, Register::RAX).unwrap(),
                Instruction::with1(Code::Pop_r64, Register::RBX).unwrap(),
            ],
            &[(VMReg::Rax, 0xDEADC0DE), (VMReg::Rsp, sp)],
            VMReg::Rbx,
            0xDEADC0DE,
        );
    }
}
