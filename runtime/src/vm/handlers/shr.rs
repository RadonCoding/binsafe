crate::vm::handlers::arithmetic!(
    shr,
    shift,
    crate::vm::bytecode::Flag::Carry.bit64()
        | crate::vm::bytecode::Flag::Overflow.bit64()
        | crate::vm::bytecode::Flag::Sign.bit64()
        | crate::vm::bytecode::Flag::Auxiliary.bit64()
        | crate::vm::bytecode::Flag::Zero.bit64()
        | crate::vm::bytecode::Flag::Parity.bit64()
);
