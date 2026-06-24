use std::{
    any::Any,
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::{
    mapper::Mapper,
    vm::encoders::{Effect, Encode},
};

static LABEL_ID: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Copy)]
pub struct Label {
    id: usize,
}

impl Label {
    pub fn new() -> Self {
        Self {
            id: LABEL_ID.fetch_add(1, Ordering::Relaxed),
        }
    }

    pub fn id(&self) -> usize {
        self.id
    }
}

impl Encode for Label {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn encode(&self, _mapper: &mut Mapper) -> Vec<u8> {
        Vec::new()
    }

    fn size(&self, _mapper: &mut Mapper) -> usize {
        0
    }

    fn reads(&self) -> Vec<Effect> {
        Vec::new()
    }

    fn writes(&self) -> Vec<Effect> {
        Vec::new()
    }

    fn depth(&self) -> i32 {
        0
    }
}
