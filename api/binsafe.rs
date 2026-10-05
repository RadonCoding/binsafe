#[macro_export]
macro_rules! binsafe {
    ($item:item) => {
        #[unsafe(link_section = ".binsafe")]
        #[inline(never)]
        $item
    };
}
