use rand::Rng;

pub fn encrypt(block: &mut Vec<u8>, key: u64, mul: u64, add: u64, att: u64) {
    let length = TryInto::<u16>::try_into(block.len()).unwrap();
    pad(block);
    encrypt_chunks(block, key, mul, add, att);
    finalize(block, length);
}

pub fn decrypt(block: &mut Vec<u8>, key: u64, mul: u64, add: u64, att: u64) {
    let length =
        u16::from_le_bytes(block.drain(0..2).collect::<Vec<u8>>().try_into().unwrap()) as usize;
    block.pop();
    decrypt_chunks(block, key, mul, add, att);
    block.truncate(length);
}

pub fn pad(block: &mut Vec<u8>) {
    let mut rng = rand::thread_rng();

    while block.len() % 8 != 0 {
        block.push(rng.gen::<u8>());
    }
}

pub fn encrypt_chunks(chunks: &mut [u8], key: u64, mul: u64, add: u64, att: u64) {
    let mut key = key ^ att;

    for chunk in chunks.chunks_exact_mut(8) {
        let mut qword = u64::from_le_bytes(chunk.try_into().unwrap());
        qword ^= key;
        chunk.copy_from_slice(&qword.to_le_bytes());
        key ^= qword;
        key = key.wrapping_mul(mul).wrapping_add(add);
    }
}

pub fn decrypt_chunks(data: &mut [u8], mut key: u64, mul: u64, add: u64, att: u64) {
    for chunk in data.chunks_exact_mut(8) {
        let qword = u64::from_le_bytes(chunk.try_into().unwrap());
        let original = qword ^ key;
        chunk.copy_from_slice(&original.to_le_bytes());
        key ^= qword ^ att;
        key = key.wrapping_mul(mul).wrapping_add(add);
    }
}

pub fn finalize(block: &mut Vec<u8>, length: u16) {
    // WORD - length of the VM-block [0..2]
    block.splice(0..0, length.to_le_bytes());
    // BYTE - lock state of the VM-block [..1]
    block.push(0);
}
