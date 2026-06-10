use iced_x86::Instruction;
use std::rc::Rc;

use crate::vm::encoders::{bit_scan_reverse::BitScanReverse, Encode};
use crate::vm::lifters::arithmetic::{self, Tail};

pub fn encode(instruction: &Instruction) -> Option<Vec<Rc<dyn Encode>>> {
    arithmetic::binary(instruction, |width| BitScanReverse { width }, Tail::Writeback)
}
