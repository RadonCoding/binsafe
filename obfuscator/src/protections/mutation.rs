use crate::protections::Protection;

#[derive(Default)]
pub struct Mutation;

impl Protection for Mutation {
    fn initialize(&mut self, engine: &mut crate::engine::Engine) {}

    fn apply(&self, engine: &mut crate::Engine) {}
}
