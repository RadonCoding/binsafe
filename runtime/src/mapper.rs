use std::{
    any::{Any, TypeId},
    collections::HashMap,
};

use rand::seq::SliceRandom as _;

pub trait Mappable: Copy + Eq + std::hash::Hash
where
    Self: 'static,
{
    const VARIANTS: &'static [Self];
    const COUNT: usize = Self::VARIANTS.len();
}

struct Mapped<T> {
    map: HashMap<T, u8>,
    variants: Vec<T>,
}

impl<T: Mappable> Mapped<T> {
    pub fn new() -> Self {
        let mut variants = T::VARIANTS.to_vec();
        variants.shuffle(&mut rand::thread_rng());

        let mut map = HashMap::with_capacity(variants.len());

        for (i, v) in variants.iter().enumerate() {
            map.insert(*v, i as u8);
        }

        Self { map, variants }
    }

    #[inline]
    pub fn index(&self, v: T) -> u8 {
        self.map[&v]
    }

    #[inline]
    pub fn from_index(&self, i: u8) -> T {
        self.variants[i as usize]
    }

    #[inline]
    pub fn count(&self) -> usize {
        self.variants.len()
    }
}

pub struct Mapper {
    maps: HashMap<TypeId, Box<dyn Any>>,
}

impl Mapper {
    pub fn new() -> Self {
        Self {
            maps: HashMap::new(),
        }
    }

    fn get<T: Mappable>(&mut self) -> &Mapped<T> {
        let id = TypeId::of::<T>();

        if !self.maps.contains_key(&id) {
            let mapped = Mapped::<T>::new();
            self.maps.insert(id, Box::new(mapped));
        }

        self.maps
            .get(&id)
            .unwrap()
            .downcast_ref::<Mapped<T>>()
            .unwrap()
    }

    #[inline]
    pub fn index<T: Mappable>(&mut self, v: T) -> u8 {
        self.get::<T>().index(v)
    }

    #[inline]
    pub fn from_index<T: Mappable>(&mut self, i: u8) -> T {
        self.get::<T>().from_index(i)
    }

    #[inline]
    pub fn count<T: Mappable>(&mut self) -> usize {
        self.get::<T>().count()
    }
}

macro_rules! mapped {
    ($ty:ident { $($v:ident),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
        pub enum $ty {
            #[doc(hidden)]
            $($v { _sealed: () }),+
        }

        #[allow(non_upper_case_globals)]
        impl $ty {
            $(
                pub const $v: Self = Self::$v { _sealed: () };
            )+
        }

        impl crate::mapper::Mappable for $ty {
            const VARIANTS: &'static [Self] = &[
                $(Self::$v),+
            ];
        }
    };
}
pub(crate) use mapped;
