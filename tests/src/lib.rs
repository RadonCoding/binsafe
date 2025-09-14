#[cfg(test)]
mod tests {
    use iced_x86::{
        code_asm::{ptr, rcx, rdx, CodeAssembler},
        Code, Instruction, Register,
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
    fn setreg64imm() {
        const EXPECTED: u64 = 0xDEADC0DE;

        let mut registers = [0u64; VM_REG_COUNT];

        let instruction = Instruction::with2(Code::Mov_r64_imm64, Register::RAX, EXPECTED).unwrap();

        let bytecode = vm::bytecode::convert(&instruction).unwrap();

        run_bytecode(&mut registers, &bytecode);

        assert_eq!(registers[(VMReg::Rax as u8 - 1) as usize], EXPECTED);
    }
}
