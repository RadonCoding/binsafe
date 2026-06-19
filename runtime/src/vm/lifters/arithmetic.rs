use iced_x86::{Instruction, Mnemonic, OpKind};
use std::rc::Rc;

use crate::vm::bytecode::{VMFlag, VMMem, VMPrecision, VMReg, VMVec, VMWidth};
use crate::vm::encoders::vector_div::VectorDiv;
use crate::vm::encoders::vector_mul::VectorMul;
use crate::vm::encoders::{
    add::Add, and::And, discard::Discard, load_address::LoadAddress, load_immediate::LoadImmediate,
    load_memory::LoadMemory, load_register::LoadRegister, load_vector::LoadVector, or::Or,
    rol::Rol, ror::Ror, sar::Sar, shl::Shl, shr::Shr, store_memory::StoreMemory,
    store_merge::StoreMerge, store_register::StoreRegister, sub::Sub, test::Test,
    vector_add::VectorAdd, vector_and::VectorAnd, vector_and_not::VectorAndNot,
    vector_or::VectorOr, vector_sub::VectorSub, vector_xor::VectorXor, xor::Xor, Encode,
};
use crate::vm::lifters::{operation_width, source};

pub enum Tail {
    Writeback,
    Discard,
}

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    match instruction.mnemonic() {
        Mnemonic::Add => binary(instruction, |width| Add { width }, Tail::Writeback),
        Mnemonic::Sub => binary(instruction, |width| Sub { width }, Tail::Writeback),
        Mnemonic::Adc => carry(instruction, |width| Add { width }),
        Mnemonic::Sbb => carry(instruction, |width| Sub { width }),
        Mnemonic::Shl => binary(instruction, |width| Shl { width }, Tail::Writeback),
        Mnemonic::Shr => binary(instruction, |width| Shr { width }, Tail::Writeback),
        Mnemonic::Sar => binary(instruction, |width| Sar { width }, Tail::Writeback),
        Mnemonic::Rol => binary(instruction, |width| Rol { width }, Tail::Writeback),
        Mnemonic::Ror => binary(instruction, |width| Ror { width }, Tail::Writeback),
        Mnemonic::Cmp => binary(instruction, |width| Sub { width }, Tail::Discard),
        Mnemonic::Test => binary(instruction, |width| Test { width }, Tail::Discard),
        Mnemonic::And => binary(instruction, |width| And { width }, Tail::Writeback),
        Mnemonic::Or => binary(instruction, |width| Or { width }, Tail::Writeback),
        Mnemonic::Xor => binary(instruction, |width| Xor { width }, Tail::Writeback),

        Mnemonic::Inc => unary(instruction, 1, false, false, |width| Add { width }),
        Mnemonic::Dec => unary(instruction, 1, false, false, |width| Sub { width }),
        Mnemonic::Neg => unary(instruction, 0, true, false, |width| Sub { width }),
        Mnemonic::Not => unary(instruction, u64::MAX, false, true, |width| Xor { width }),

        Mnemonic::Pand | Mnemonic::Andps | Mnemonic::Andpd | Mnemonic::Vandps => {
            vector(instruction, |width| VectorAnd { width })
        }
        Mnemonic::Por | Mnemonic::Orps | Mnemonic::Orpd => {
            vector(instruction, |width| VectorOr { width })
        }
        Mnemonic::Pxor | Mnemonic::Xorps | Mnemonic::Xorpd | Mnemonic::Vpxor | Mnemonic::Vxorps => {
            vector(instruction, |width| VectorXor { width })
        }
        Mnemonic::Pandn | Mnemonic::Andnps | Mnemonic::Andnpd => {
            vector(instruction, |width| VectorAndNot { width })
        }

        Mnemonic::Paddb => vector(instruction, |width| VectorAdd {
            width,
            stride: VMWidth::Lower8,
            precision: VMPrecision::Integer,
        }),
        Mnemonic::Paddw => vector(instruction, |width| VectorAdd {
            width,
            stride: VMWidth::Lower16,
            precision: VMPrecision::Integer,
        }),
        Mnemonic::Paddd => vector(instruction, |width| VectorAdd {
            width,
            stride: VMWidth::Lower32,
            precision: VMPrecision::Integer,
        }),
        Mnemonic::Addps | Mnemonic::Vaddps => vector(instruction, |width| VectorAdd {
            width,
            stride: VMWidth::Lower32,
            precision: VMPrecision::Float,
        }),
        Mnemonic::Paddq => vector(instruction, |width| VectorAdd {
            width,
            stride: VMWidth::Lower64,
            precision: VMPrecision::Integer,
        }),
        Mnemonic::Addpd | Mnemonic::Vaddpd => vector(instruction, |width| VectorAdd {
            width,
            stride: VMWidth::Lower64,
            precision: VMPrecision::Float,
        }),

        Mnemonic::Psubb => vector(instruction, |width| VectorSub {
            width,
            stride: VMWidth::Lower8,
            precision: VMPrecision::Integer,
        }),
        Mnemonic::Psubw => vector(instruction, |width| VectorSub {
            width,
            stride: VMWidth::Lower16,
            precision: VMPrecision::Integer,
        }),
        Mnemonic::Psubd => vector(instruction, |width| VectorSub {
            width,
            stride: VMWidth::Lower32,
            precision: VMPrecision::Integer,
        }),
        Mnemonic::Subps | Mnemonic::Vsubps => vector(instruction, |width| VectorSub {
            width,
            stride: VMWidth::Lower32,
            precision: VMPrecision::Float,
        }),
        Mnemonic::Psubq => vector(instruction, |width| VectorSub {
            width,
            stride: VMWidth::Lower64,
            precision: VMPrecision::Integer,
        }),
        Mnemonic::Subpd | Mnemonic::Vsubpd => vector(instruction, |width| VectorSub {
            width,
            stride: VMWidth::Lower64,
            precision: VMPrecision::Float,
        }),

        Mnemonic::Pmulld | Mnemonic::Vpmulld => vector(instruction, |width| VectorMul {
            width,
            stride: VMWidth::Lower32,
            precision: VMPrecision::Integer,
        }),
        Mnemonic::Pmullw | Mnemonic::Vpmullw => vector(instruction, |width| VectorMul {
            width,
            stride: VMWidth::Lower16,
            precision: VMPrecision::Integer,
        }),
        Mnemonic::Pmulhw | Mnemonic::Vpmulhw => vector(instruction, |width| VectorMul {
            width,
            stride: VMWidth::Higher16,
            precision: VMPrecision::Integer,
        }),
        Mnemonic::Mulps | Mnemonic::Vmulps => vector(instruction, |width| VectorMul {
            width,
            stride: VMWidth::Lower32,
            precision: VMPrecision::Float,
        }),
        Mnemonic::Mulpd | Mnemonic::Vmulpd => vector(instruction, |width| VectorMul {
            width,
            stride: VMWidth::Lower64,
            precision: VMPrecision::Float,
        }),

        Mnemonic::Divps | Mnemonic::Vdivps => vector(instruction, |width| VectorDiv {
            width,
            stride: VMWidth::Lower32,
        }),
        Mnemonic::Divpd | Mnemonic::Vdivpd => vector(instruction, |width| VectorDiv {
            width,
            stride: VMWidth::Lower64,
        }),

        mnemonic => panic!("unsupported mnemonic: {mnemonic:?}"),
    }
}

pub fn binary<O: Encode + 'static>(
    instruction: &Instruction,
    make: impl Fn(VMWidth) -> O,
    tail: Tail,
) -> Option<Vec<Rc<dyn Encode>>> {
    let mut operations = Vec::<Rc<dyn Encode>>::new();

    let width = operation_width(instruction, 0);

    source(&mut operations, instruction, 0, width).unwrap();
    source(&mut operations, instruction, 1, width).unwrap();

    operations.push(Rc::new(make(width)));

    match tail {
        Tail::Writeback => match instruction.op0_kind() {
            OpKind::Register => {
                operations.push(Rc::new(StoreRegister {
                    width,
                    destination: VMReg::from(instruction.op0_register()),
                }));
            }
            OpKind::Memory => {
                operations.push(Rc::new(LoadAddress {
                    source: VMMem::from(instruction),
                }));
                operations.push(Rc::new(StoreMemory { width }));
            }
            _ => unreachable!(),
        },
        Tail::Discard => {
            operations.push(Rc::new(Discard));
        }
    }
    Some(operations)
}

pub fn carry<O: Encode + 'static>(
    instruction: &Instruction,
    make: impl Fn(VMWidth) -> O,
) -> Option<Vec<Rc<dyn Encode>>> {
    let mut operations = Vec::<Rc<dyn Encode>>::new();
    let width = operation_width(instruction, 0);

    source(&mut operations, instruction, 0, width);
    source(&mut operations, instruction, 1, width);

    operations.push(Rc::new(LoadRegister {
        width: VMWidth::Lower64,
        source: VMReg::Flags,
    }));
    operations.push(Rc::new(LoadImmediate {
        width: VMWidth::Lower64,
        source: VMFlag::Carry.bit64().to_le_bytes().to_vec(),
    }));
    operations.push(Rc::new(And {
        width: VMWidth::Lower64,
    }));

    operations.push(Rc::new(Add { width }));

    operations.push(Rc::new(make(width)));

    match instruction.op0_kind() {
        OpKind::Register => {
            operations.push(Rc::new(StoreRegister {
                width,
                destination: VMReg::from(instruction.op0_register()),
            }));
        }
        OpKind::Memory => {
            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(StoreMemory { width }));
        }
        _ => unreachable!(),
    };

    Some(operations)
}

fn unary<O: Encode + 'static>(
    instruction: &Instruction,
    immediate: u64,
    reverse: bool,
    preserve: bool,
    make: impl Fn(VMWidth) -> O,
) -> Option<Vec<Rc<dyn Encode>>> {
    let mut operations = Vec::<Rc<dyn Encode>>::new();

    let width = operation_width(instruction, 0);

    if preserve {
        operations.push(Rc::new(LoadRegister {
            width: VMWidth::Lower64,
            source: VMReg::Flags,
        }));
    }

    if reverse {
        operations.push(Rc::new(LoadImmediate {
            width,
            source: immediate.to_le_bytes()[..width.size()].to_vec(),
        }));
        source(&mut operations, instruction, 0, width);
    } else {
        source(&mut operations, instruction, 0, width);
        operations.push(Rc::new(LoadImmediate {
            width,
            source: immediate.to_le_bytes()[..width.size()].to_vec(),
        }));
    }

    operations.push(Rc::new(make(width)));

    match instruction.op0_kind() {
        OpKind::Register => {
            let destination_register = VMReg::from(instruction.op0_register());
            operations.push(Rc::new(StoreRegister {
                width,
                destination: destination_register,
            }));
        }
        OpKind::Memory => {
            operations.push(Rc::new(LoadAddress {
                source: VMMem::from(instruction),
            }));
            operations.push(Rc::new(StoreMemory { width }));
        }
        _ => unreachable!(),
    }

    if preserve {
        operations.push(Rc::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: VMReg::Flags,
        }));
    }

    Some(operations)
}

fn vector<O: Encode + 'static>(
    instruction: &Instruction,
    make: impl Fn(VMWidth) -> O,
) -> Option<Vec<Rc<dyn Encode>>> {
    let mut operations = Vec::<Rc<dyn Encode>>::new();

    let destination = VMVec::from(instruction.op0_register());

    let width = if instruction.op0_register().is_ymm() {
        VMWidth::Lower256
    } else {
        VMWidth::Lower128
    };

    let (first, second) = if instruction.op_count() == 3 {
        (1, 2)
    } else {
        (0, 1)
    };

    for &index in &[first, second] {
        match instruction.op_kind(index) {
            OpKind::Register => {
                operations.push(Rc::new(LoadVector {
                    width,
                    source: VMVec::from(instruction.op_register(index)),
                }));
            }
            OpKind::Memory => {
                operations.push(Rc::new(LoadAddress {
                    source: VMMem::from(instruction),
                }));
                operations.push(Rc::new(LoadMemory { width }));
            }
            _ => unreachable!(),
        }
    }

    operations.push(Rc::new(make(width)));

    operations.push(Rc::new(StoreMerge { width, destination }));

    Some(operations)
}
