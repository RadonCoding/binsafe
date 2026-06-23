use crate::runtime::Runtime;
use crate::vm::utils::scratch;
use iced_x86::code_asm::*;

// unsigned char* (unsigned char*)
pub fn build(rt: &mut Runtime) {
    // rdtsc
    rt.asm.rdtsc().unwrap();
    // store rax
    scratch::store(rt, r12, rax);
    // store rdx
    scratch::store(rt, r12, rdx);
    // mov rax, rcx
    rt.asm.mov(rax, rcx).unwrap();
    // ret
    rt.asm.ret().unwrap();
}
