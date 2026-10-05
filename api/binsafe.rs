#[macro_export]
macro_rules! binsafe {
    ($item:item) => {
        #[link_section = ".binsafe"]
        #[inline(never)]
        $item
    };
}
