crate::vm::handlers::arithmetic!(
    or,
    r8,
    crate::vm::bytecode::VMFlag::Carry.bit64()
        | crate::vm::bytecode::VMFlag::Overflow.bit64()
        | crate::vm::bytecode::VMFlag::Sign.bit64()
        | crate::vm::bytecode::VMFlag::Auxiliary.bit64()
        | crate::vm::bytecode::VMFlag::Zero.bit64()
        | crate::vm::bytecode::VMFlag::Parity.bit64()
);
