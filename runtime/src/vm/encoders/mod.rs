use crate::mapper::Mapper;

pub trait Encode {
    fn encode(&mut self, mapper: &mut Mapper) -> Vec<u8>;
}

pub mod jcc;
pub mod nop;
