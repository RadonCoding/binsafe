use crate::{mapper::Mapper, vm::encoders::Encode};
use std::{
    any::Any,
    sync::atomic::{AtomicUsize, Ordering},
};

static LABEL_ID: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelKind {
    Marker,
    Target,
}

#[derive(Debug, Clone, Copy)]
pub struct Label {
    id: usize,
    kind: LabelKind,
}

impl Label {
    pub fn marker() -> Self {
        Self {
            id: LABEL_ID.fetch_add(1, Ordering::Relaxed),
            kind: LabelKind::Marker,
        }
    }

    pub fn target() -> Self {
        Self {
            id: LABEL_ID.fetch_add(1, Ordering::Relaxed),
            kind: LabelKind::Target,
        }
    }

    pub fn id(&self) -> usize {
        self.id
    }

    pub fn is_marker(&self) -> bool {
        self.kind == LabelKind::Marker
    }

    pub fn is_target(&self) -> bool {
        self.kind == LabelKind::Target
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
}
