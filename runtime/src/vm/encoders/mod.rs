use crate::mapper::Mapper;

pub trait Encode {
    fn encode(&self, mapper: &mut Mapper) -> Vec<u8>;
}

pub mod arithmetic;
pub mod branch;
pub mod jcc;
pub mod load;
pub mod nop;
pub mod stack;
pub mod store;
