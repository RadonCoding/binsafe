#[cfg(debug_assertions)]
pub mod debug;
pub mod functions;
pub mod mapper;
pub mod runtime;
pub mod vm;

macro_rules! stack {
    ($name:ident, $offset:expr, $size:expr) => {
        let $name = $offset;
        $offset += $size;
    };
}

pub(crate) use stack;

pub const VM_STACK_SIZE: u64 = 0x1000;
pub const VM_SCRATCH_SIZE: u64 = 0x1000;
#[cfg(debug_assertions)]
pub const VM_DEBUG_SIZE: u64 = 0x100;

// PUSH imm32 + CALL rel32
pub const VM_DISPATCH_SIZE: usize = 10;

// JMP rel32
pub const VM_TRAMPOLINE_SIZE: usize = 5;
