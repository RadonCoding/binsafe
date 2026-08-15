crate::vm::handlers::arithmetic!(
    sub,
    r8,
    crate::vm::bytecode::Flag::Carry.bit64()
        | crate::vm::bytecode::Flag::Overflow.bit64()
        | crate::vm::bytecode::Flag::Sign.bit64()
        | crate::vm::bytecode::Flag::Auxiliary.bit64()
        | crate::vm::bytecode::Flag::Zero.bit64()
        | crate::vm::bytecode::Flag::Parity.bit64()
);
