include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../api/generated/binsafe.rs"
));

use std::time::Instant;

fn main() {
    let key: [u32; 4] = [0xA3B1C2D3, 0xE4F50617, 0x28394A5B, 0x6C7D8E9F];
    let delta: u32 = 0x9E3779B9;

    let mut data_native: [u32; 2] = [0x12345678, 0x9ABCDEF0];

    let start_native = Instant::now();

    let mut v0_native = data_native[0];
    let mut v1_native = data_native[1];

    for _ in 0..200000 {
        let mut sum: u32 = 0;

        for _ in 0..32 {
            v0_native = v0_native.wrapping_add(
                (((v1_native << 4) ^ (v1_native >> 5)).wrapping_add(v1_native))
                    ^ sum.wrapping_add(key[(sum & 3) as usize]),
            );
            sum = sum.wrapping_add(delta);
            v1_native = v1_native.wrapping_add(
                (((v0_native << 4) ^ (v0_native >> 5)).wrapping_add(v0_native))
                    ^ sum.wrapping_add(key[((sum >> 11) & 3) as usize]),
            );
        }
    }

    data_native[0] = v0_native;
    data_native[1] = v1_native;

    let end_native = Instant::now();
    let elapsed_native = end_native.duration_since(start_native);

    let mut data_virtualized: [u32; 2] = [0x12345678, 0x9ABCDEF0];

    let start_virtualized = Instant::now();

    binsafe_begin!();

    let mut v0_virtualized = data_virtualized[0];
    let mut v1_virtualized = data_virtualized[1];

    for _ in 0..200000 {
        let mut sum: u32 = 0;

        for _ in 0..32 {
            v0_virtualized = v0_virtualized.wrapping_add(
                (((v1_virtualized << 4) ^ (v1_virtualized >> 5)).wrapping_add(v1_virtualized))
                    ^ sum.wrapping_add(key[(sum & 3) as usize]),
            );
            sum = sum.wrapping_add(delta);
            v1_virtualized = v1_virtualized.wrapping_add(
                (((v0_virtualized << 4) ^ (v0_virtualized >> 5)).wrapping_add(v0_virtualized))
                    ^ sum.wrapping_add(key[((sum >> 11) & 3) as usize]),
            );
        }
    }

    data_virtualized[0] = v0_virtualized;
    data_virtualized[1] = v1_virtualized;

    binsafe_end!();

    let end_virtualized = Instant::now();
    let elapsed_virtualized = end_virtualized.duration_since(start_virtualized);

    let native_ms = elapsed_native.as_secs_f64() * 1000.0;
    let virtualized_ms = elapsed_virtualized.as_secs_f64() * 1000.0;

    println!("Native: {} ms", native_ms);
    println!("Virtualized: {} ms", virtualized_ms);
    println!("Overhead: {}x", virtualized_ms / native_ms);
}
