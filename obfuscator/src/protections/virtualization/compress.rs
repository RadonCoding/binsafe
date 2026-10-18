fn length_bits(position: usize) -> u32 {
    let mut offset = 4;

    while (1usize << offset) < position {
        offset += 1;
    }

    16 - offset
}

fn compress_chunk(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    let mut cursor = 0;

    while cursor < data.len() {
        let group = output.len();
        output.push(0);

        let mut flags = 0u8;

        for bit in 0..8 {
            if cursor >= data.len() {
                break;
            }

            let bits = length_bits(cursor);
            let window = 1usize << (16 - bits);
            let longest = (1usize << bits) - 1 + 3;

            let start = cursor.saturating_sub(window);

            let mut best_length = 0;
            let mut best_offset = 0;

            for candidate in start..cursor {
                let mut length = 0;

                while cursor + length < data.len()
                    && length < longest
                    && data[candidate + length] == data[cursor + length]
                {
                    length += 1;
                }

                if length > best_length {
                    best_length = length;
                    best_offset = cursor - candidate;
                }
            }

            if best_length >= 3 {
                let token = (((best_offset - 1) as u16) << bits) | ((best_length - 3) as u16);
                output.extend_from_slice(&token.to_le_bytes());
                flags |= 1 << bit;
                cursor += best_length;
            } else {
                output.push(data[cursor]);
                cursor += 1;
            }
        }

        output[group] = flags;
    }

    output
}

pub fn compress(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();

    for chunk in data.chunks(4096) {
        let compressed = compress_chunk(chunk);

        if compressed.len() < chunk.len() {
            let header = 0xB000u16 | (compressed.len() - 1) as u16;
            output.extend_from_slice(&header.to_le_bytes());
            output.extend_from_slice(&compressed);
        } else {
            let header = 0x3000u16 | (chunk.len() - 1) as u16;
            output.extend_from_slice(&header.to_le_bytes());
            output.extend_from_slice(chunk);
        }
    }

    output
}
