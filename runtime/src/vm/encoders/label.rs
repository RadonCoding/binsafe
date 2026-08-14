use crate::{mapper::Mapper, vm::encoders::Encode};
use std::{
    any::Any,
    sync::atomic::{AtomicUsize, Ordering},
};

static LABEL_ID: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelKind {
    Source,
    Destination,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Label {
    id: usize,
    kind: LabelKind,
}

impl Label {
    pub fn source() -> Self {
        Self {
            id: LABEL_ID.fetch_add(1, Ordering::Relaxed),
            kind: LabelKind::Source,
        }
    }

    pub fn destination() -> Self {
        Self {
            id: LABEL_ID.fetch_add(1, Ordering::Relaxed),
            kind: LabelKind::Destination,
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
        vec![]
    }

    fn is_source(&self) -> bool {
        self.kind == LabelKind::Source
    }

    fn is_destination(&self) -> bool {
        self.kind == LabelKind::Destination
    }
}
