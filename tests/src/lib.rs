#[cfg(test)]
mod tests {
    use std::{ffi::c_void, mem, ptr};

    use iced_x86::{
        code_asm::{ptr, rcx, rdx},
        Code, Instruction, Register,
    };
    use runtime::{
        runtime::{DataDef, FnDef, Runtime},
        vm::{
            bytecode::{self, VMOp, VMReg, VM_REG_COUNT},
            stack,
        },
    };
    use windows::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    };

    struct Executor {
        mem: *mut c_void,
        size: usize,
    }

    impl Executor {
        fn new(size: usize) -> Self {
            let mem = unsafe {
                VirtualAlloc(None, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
            };
            Self { mem, size }
        }

        fn run(&self, registers: &mut [u64], bytecode: &[u8]) {
            let mut rt = Runtime::new(64);

            let dispatch = rt.func_labels[&FnDef::VmDispatch];

            // call ...
            rt.asm
                .call(rt.func_labels[&FnDef::InitializeStack])
                .unwrap();

            // mov rcx, ...
            rt.asm.mov(rcx, registers.as_mut_ptr() as u64).unwrap();
            // lea rdx, [...]
            rt.asm
                .lea(rdx, ptr(rt.data_labels[&DataDef::VmCode]))
                .unwrap();
            // call ...
            stack::call(&mut rt, dispatch);
            // ret
            rt.asm.ret().unwrap();

            rt.define_data(DataDef::VmCode, bytecode);

            let ip = self.mem as u64;

            let code = rt.assemble(ip);

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

    fn template(instruction: Instruction, setup: &[(VMReg, u64)], target: VMReg, expected: u64) {
        let executor = Executor::new(0x2000);

        let mut registers = [0u64; VM_REG_COUNT];

        for (reg, val) in setup {
            registers[(*reg as u8 - 1) as usize] = *val;
        }

        let mut bytecode = bytecode::convert(0, &instruction).unwrap();

        bytecode.push(VMOp::Invalid as u8);

        executor.run(&mut registers, &bytecode);

        assert_eq!(
            registers[(target as u8 - 1) as usize],
            expected,
            "Failed: {:?} | Expected: 0x{:X}, Got: 0x{:X}",
            instruction,
            expected,
            registers[(target as u8 - 1) as usize]
        );
    }

    #[test]
    fn test_mov_reg_imm() {
        template(
            Instruction::with2(Code::Mov_r32_imm32, Register::EAX, 0x0000_0000u32).unwrap(),
            &[(VMReg::Rax, 0xFFFF_FFFF_FFFF_FFFF)],
            VMReg::Rax,
            0x0000_0000_0000_0000,
        );
    }
}
