#[cfg(debug_assertions)]
pub mod debug;
pub mod functions;
pub mod mapper;
pub mod runtime;
pub mod utils;
pub mod vm;

macro_rules! stack {
    ($name:ident, $offset:expr, $size:expr) => {
        let $name = $offset;
        $offset += $size;
    };
}

pub(crate) use stack;

pub const VM_STACK_SIZE: u64 = 0x100000;
pub const VM_SCRATCH_SIZE: u64 = 0x1000;
#[cfg(debug_assertions)]
pub const VM_DEBUG_SIZE: u64 = 0x100;

// PUSH imm32 + CALL rel32
pub const VM_DISPATCH_SIZE: usize = 10;

// MOV dword [rsp], imm32 + CALL rel32
pub const VM_REDIRECT_SIZE: usize = 12;

// CALL rel32
pub const VM_TRAMPOLINE_SIZE: usize = 5;

pub const VM_INTEGRITY_QWORD: u64 = 0xFA11ED175001FA11;

pub const VM_CIPHER_ROUNDS: u32 = 27;
