use exe::{Buffer, ImageDirectoryEntry, PETranslation, VecPE, PE};
use std::{collections::HashSet, mem::size_of};

#[repr(C, packed)]
struct RuntimeFunction {
    begin_address: u32,
    end_address: u32,
    unwind_info_address: u32,
}

pub fn get_exception_handlers(pe: &VecPE) -> HashSet<u32> {
    let mut handlers = HashSet::new();

    let exceptions = pe
        .get_data_directory(ImageDirectoryEntry::Exception)
        .unwrap();

    if exceptions.virtual_address.0 == 0 || exceptions.size == 0 {
        return handlers;
    }

    let offset = pe
        .translate(PETranslation::Memory(exceptions.virtual_address))
        .unwrap();
    let count = exceptions.size as usize / size_of::<RuntimeFunction>();
    let functions = pe.get_slice_ref::<RuntimeFunction>(offset, count).unwrap();

    let mut unwinds = Vec::new();

    for rf in functions {
        handlers.insert(rf.begin_address);

        if rf.unwind_info_address != 0 {
            unwinds.push(rf.unwind_info_address);
        }
    }

    unwinds.sort_unstable();
    unwinds.dedup();

    for rva in unwinds {
        get_exception_unwinders(pe, rva, &mut handlers);
    }

    handlers
}

fn get_exception_unwinders(pe: &VecPE, rva: u32, handlers: &mut HashSet<u32>) {
    let offset = match pe.translate(PETranslation::Memory(rva.into())) {
        Ok(o) => o,
        Err(_) => return,
    };

    let header = match pe.get_slice_ref::<u8>(offset, 4) {
        Ok(h) => h,
        Err(_) => return,
    };

    let version = header[0] & 0x07;
    let flags = header[0] >> 3;
    let codes = header[2] as usize;

    if version != 1 {
        return;
    }

    let mut position = 4 + codes * 2;

    if position % 4 != 0 {
        position += 4 - (position % 4);
    }

    if flags & 0x04 != 0 {
        let bytes = match pe.get_slice_ref::<u8>(offset, position + 12) {
            Ok(b) => b,
            Err(_) => return,
        };

        let chained = u32::from_le_bytes(bytes[pos + 8..position + 12].try_into().unwrap());

        handlers.insert(chained);

        get_exception_unwinders(pe, chained, handlers);

        return;
    }

    if flags & 0x03 == 0 {
        return;
    }

    let bytes = match pe.get_slice_ref::<u8>(offset, position + 4) {
        Ok(b) => b,
        Err(_) => return,
    };

    let handler = u32::from_le_bytes(bytes[position..position + 4].try_into().unwrap());

    handlers.insert(handler);

    position += 4;

    let section = match pe
        .get_section_table()
        .unwrap()
        .iter()
        .find(|s| rva >= s.virtual_address.0 && rva < s.virtual_address.0 + s.virtual_size)
    {
        Some(s) => s,
        None => return,
    };

    let base = pe
        .translate(PETranslation::Memory(section.virtual_address))
        .unwrap();
    let end = base + section.size_of_raw_data as usize;
    let start = offset + position;

    if start >= end {
        return;
    }

    let bytes = match pe.get_slice_ref::<u8>(start, end - start) {
        Ok(b) => b,
        Err(_) => return,
    };

    for chunk in bytes.chunks_exact(4) {
        let rva = u32::from_le_bytes(chunk.try_into().unwrap());
        handlers.insert(rva);
    }
}
