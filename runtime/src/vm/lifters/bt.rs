use iced_x86::{Instruction, Mnemonic};
use std::rc::Rc;

use crate::vm::encoders::{
    bit_test::BitTest, bit_test_complement::BitTestComplement, bit_test_reset::BitTestReset,
    bit_test_set::BitTestSet, Encode,
};
use crate::vm::lifters::arithmetic::{self, Tail};

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    match instruction.mnemonic() {
        Mnemonic::Bt => arithmetic::binary(instruction, |width| BitTest { width }, Tail::Discard),
        Mnemonic::Bts => {
            arithmetic::binary(instruction, |width| BitTestSet { width }, Tail::Writeback)
        }
        Mnemonic::Btr => {
            arithmetic::binary(instruction, |width| BitTestReset { width }, Tail::Writeback)
        }
        Mnemonic::Btc => arithmetic::binary(
            instruction,
            |width| BitTestComplement { width },
            Tail::Writeback,
        ),
        mnemonic => panic!("unsupported mnemonic: {mnemonic:?}"),
    }
}
