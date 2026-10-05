include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../api/binsafe.rs"
));

binsafe! {
    fn hello() {
        println!("Hello, world!");
    }
}

fn main() {
    hello();
}
