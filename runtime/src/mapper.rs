use std::{
    any::{Any, TypeId},
    collections::HashMap,
};

use rand::seq::SliceRandom as _;

pub trait MappedSpec: Copy + Eq + std::hash::Hash
where
    Self: 'static,
{
    const VARIANTS: &'static [Self];
    const COUNT: usize = Self::VARIANTS.len();
}

struct Mapper<T> {
    map: HashMap<T, u8>,
    variants: Vec<T>,
}

impl<T: MappedSpec> Mapper<T> {
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

pub struct MapperRegistry {
    maps: HashMap<TypeId, Box<dyn Any>>,
}

impl MapperRegistry {
    pub fn new() -> Self {
        Self {
            maps: HashMap::new(),
        }
    }

    fn get<T: MappedSpec>(&mut self) -> &Mapper<T> {
        let id = TypeId::of::<T>();

        if !self.maps.contains_key(&id) {
            let mapper = Mapper::<T>::new();
            self.maps.insert(id, Box::new(mapper));
        }

        self.maps
            .get(&id)
            .unwrap()
            .downcast_ref::<Mapper<T>>()
            .unwrap()
    }

    #[inline]
    pub fn index<T: MappedSpec>(&mut self, v: T) -> u8 {
        self.get::<T>().index(v)
    }

    #[inline]
    pub fn from_index<T: MappedSpec>(&mut self, i: u8) -> T {
        self.get::<T>().from_index(i)
    }

    #[inline]
    pub fn count<T: MappedSpec>(&mut self) -> usize {
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

        impl crate::mapper::MappedSpec for $ty {
            const VARIANTS: &'static [Self] = &[
                $(Self::$v),+
            ];
        }
    };
}
pub(crate) use mapped;
