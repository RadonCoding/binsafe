use crate::engine::Engine;

pub mod mutation;
pub mod virtualization;

pub trait Protection {
    fn initialize(&mut self, engine: &mut Engine);

    fn apply(&self, engine: &mut Engine);
}
