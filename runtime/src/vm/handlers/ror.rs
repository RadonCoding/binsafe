crate::vm::handlers::arithmetic!(
    ror,
    shift,
    crate::vm::bytecode::VMFlag::Carry.bit64() | crate::vm::bytecode::VMFlag::Overflow.bit64()
);
