include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../api/generated/binsafe.rs"
));

fn main() {
    binsafe_begin!();
    println!("Hello, world!");
    binsafe_end!();
}
