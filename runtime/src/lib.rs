pub mod assembler;
#[cfg(debug_assertions)]
pub mod debug;
pub mod functions;
pub mod mapper;
pub mod runtime;
pub mod vm;

macro_rules! define_offset {
    ($name:ident, $offset:expr, $size:expr) => {
        $offset += $size;
        let $name = $offset;
    };
}

pub(crate) use define_offset;

pub const VM_STACK_SIZE: u64 = 0x1000;
pub const VM_SCRATCH_SIZE: u64 = 0x1000;

// PUSH imm32 + CALL rel32
pub const VM_DISPATCH_SIZE: usize = 10;

// JMP rel32
pub const VM_TRAMPOLINE_SIZE: usize = 5;
