#[cfg(test)]
mod tests {

    use iced_x86::{
        code_asm::{ptr, rcx, rdx, CodeAssembler},
        Code, Instruction, MemoryOperand, Register,
    };
    use runtime::{
        runtime::{DataDef, FnDef, Runtime},
        vm::{
            self,
            bytecode::{VMReg, VM_REG_COUNT},
        },
    };
    use windows::Win32::System::Memory::{
        VirtualAlloc, VirtualFree, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE,
    };

    fn run_bytecode(registers: &mut [u64], bytecode: &[u8]) {
        let mut asm = CodeAssembler::new(64).unwrap();
        let mut rt = Runtime::new(&mut asm);

        rt.asm.call(rt.func_labels[&FnDef::VmInitialize]).unwrap();

        rt.asm.mov(rcx, registers.as_ptr() as u64).unwrap();
        rt.asm
            .lea(rdx, ptr(rt.data_labels[&DataDef::BYTECODE]))
            .unwrap();
        rt.asm.call(rt.func_labels[&FnDef::VmDispatcher]).unwrap();

        rt.asm.ret().unwrap();

        rt.define_data(DataDef::BYTECODE, bytecode);

        let mem = unsafe {
            VirtualAlloc(
                None,
                0x1000,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
        };

        let ip = mem as u64;

        let code = rt.assemble(ip);

        unsafe { std::ptr::copy_nonoverlapping(code.as_ptr(), mem as *mut u8, code.len()) };

        let entry_point: extern "C" fn() -> u64 = unsafe { std::mem::transmute(mem) };

        entry_point();

        unsafe {
            VirtualFree(mem, 0, MEM_RELEASE).unwrap();
        }
    }

    #[test]
    fn pushreg64() {
        const EXPECTED: u64 = 0xDECEA5ED;

        let mut stack = [0u8; 0x8];

        let mut registers = [0u64; VM_REG_COUNT];
        registers[(VMReg::Rax as u8 - 1) as usize] = EXPECTED;
        registers[(VMReg::Rsp as u8 - 1) as usize] = stack.as_mut_ptr() as u64 + stack.len() as u64;

        let instruction = Instruction::with1(Code::Push_r64, Register::RAX).unwrap();

        let bytecode = vm::bytecode::convert(&instruction).unwrap();

        run_bytecode(&mut registers, &bytecode);

        let sp = registers[(VMReg::Rsp as u8 - 1) as usize] as *const u8;

        assert_eq!(unsafe { *(sp as *const u64) }, EXPECTED);
    }

    #[test]
    fn setreg64imm() {
        const EXPECTED: u64 = 0xDECEA5ED;

        let mut registers = [0u64; VM_REG_COUNT];

        let instruction = Instruction::with2(Code::Mov_r64_imm64, Register::RAX, EXPECTED).unwrap();

        let bytecode = vm::bytecode::convert(&instruction).unwrap();

        run_bytecode(&mut registers, &bytecode);

        assert_eq!(registers[(VMReg::Rax as u8 - 1) as usize], EXPECTED);
    }

    #[test]
    fn setregreg64() {
        const EXPECTED: u64 = 0xDECEA5ED;

        let mut registers = [0u64; VM_REG_COUNT];
        registers[(VMReg::Rcx as u8 - 1) as usize] = EXPECTED;

        let instruction =
            Instruction::with2(Code::Mov_rm64_r64, Register::RAX, Register::RCX).unwrap();

        let bytecode = vm::bytecode::convert(&instruction).unwrap();

        run_bytecode(&mut registers, &bytecode);

        assert_eq!(registers[(VMReg::Rax as u8 - 1) as usize], EXPECTED);
    }

    #[test]
    fn setregreg32() {
        const PREEXISTING: u64 = 0xFFFF_FFFF_FFFF_FFFF;
        const EXPECTED_DWORD: u32 = 0xDECEA5ED;
        const EXPECTED: u64 = EXPECTED_DWORD as u64;

        let mut registers = [0u64; VM_REG_COUNT];
        registers[(VMReg::Rax as u8 - 1) as usize] = PREEXISTING;
        registers[(VMReg::Rcx as u8 - 1) as usize] = EXPECTED_DWORD as u64;

        let instruction =
            Instruction::with2(Code::Mov_rm32_r32, Register::EAX, Register::ECX).unwrap();

        let bytecode = vm::bytecode::convert(&instruction).unwrap();

        run_bytecode(&mut registers, &bytecode);

        assert_eq!(registers[(VMReg::Rax as u8 - 1) as usize], EXPECTED);
    }

    #[test]
    fn setregreg16() {
        const PREEXISTING: u64 = 0xFFFF_FFFF_FFFF_FFFF;
        const EXPECTED_WORD: u16 = 0xDEAD;
        const EXPECTED: u64 = (PREEXISTING & 0xFFFF_FFFF_FFFF_0000) | (EXPECTED_WORD as u64);

        let mut registers = [0u64; VM_REG_COUNT];
        registers[(VMReg::Rax as u8 - 1) as usize] = PREEXISTING;
        registers[(VMReg::Rcx as u8 - 1) as usize] = EXPECTED_WORD as u64;

        let instruction =
            Instruction::with2(Code::Mov_rm16_r16, Register::AX, Register::CX).unwrap();

        let bytecode = vm::bytecode::convert(&instruction).unwrap();

        run_bytecode(&mut registers, &bytecode);

        assert_eq!(registers[(VMReg::Rax as u8 - 1) as usize], EXPECTED);
    }

    #[test]
    fn setregreg8() {
        const PREEXISTING: u64 = 0xFFFF_FFFF_FFFF_FFFF;
        const EXPECTED_BYTE: u8 = 0xDD;
        const EXPECTED: u64 = (PREEXISTING & 0xFFFF_FFFF_FFFF_00FF) | ((EXPECTED_BYTE as u64) << 8);

        let mut registers = [0u64; VM_REG_COUNT];
        registers[(VMReg::Rax as u8 - 1) as usize] = PREEXISTING;
        registers[(VMReg::Rcx as u8 - 1) as usize] = EXPECTED_BYTE as u64;

        let instruction = Instruction::with2(Code::Mov_rm8_r8, Register::AH, Register::CH).unwrap();

        let bytecode = vm::bytecode::convert(&instruction).unwrap();

        run_bytecode(&mut registers, &bytecode);

        assert_eq!(registers[(VMReg::Rax as u8 - 1) as usize], EXPECTED);
    }

    #[test]
    fn setreg64mem() {
        const EXPECTED: u64 = 0xDECEA5ED;

        let mut registers = [0u64; VM_REG_COUNT];
        registers[(VMReg::Rcx as u8 - 1) as usize] = &EXPECTED as *const u64 as u64;

        let instruction = Instruction::with2(
            Code::Mov_r64_rm64,
            Register::RAX,
            MemoryOperand::with_base(Register::RCX),
        )
        .unwrap();

        let bytecode = vm::bytecode::convert(&instruction).unwrap();

        run_bytecode(&mut registers, &bytecode);

        assert_eq!(registers[(VMReg::Rax as u8 - 1) as usize], EXPECTED);
    }

    #[test]
    fn setmemreg64() {
        const EXPECTED: u64 = 0xDECEA5ED;

        let mut rax = 0u64;

        let mut registers = [0u64; VM_REG_COUNT];
        registers[(VMReg::Rax as u8 - 1) as usize] = &mut rax as *mut u64 as u64;
        registers[(VMReg::Rcx as u8 - 1) as usize] = EXPECTED;

        let instruction = Instruction::with2(
            Code::Mov_rm64_r64,
            MemoryOperand::with_base(Register::RAX),
            Register::RCX,
        )
        .unwrap();

        let bytecode = vm::bytecode::convert(&instruction).unwrap();

        run_bytecode(&mut registers, &bytecode);

        assert_eq!(rax, EXPECTED);
    }
}
