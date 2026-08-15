crate::vm::handlers::arithmetic!(
    ror,
    shift,
    crate::vm::bytecode::Flag::Carry.bit64() | crate::vm::bytecode::Flag::Overflow.bit64()
);
