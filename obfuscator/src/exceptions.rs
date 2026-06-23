use exe::{Buffer, ImageDirectoryEntry, PETranslation, VecPE, PE};
use std::collections::HashSet;

#[repr(C, packed)]
struct RuntimeFunction {
    begin_address: u32,
    end_address: u32,
    unwind_info_address: u32,
}

pub fn get_exception_handlers(pe: &VecPE) -> HashSet<u32> {
    let mut results = HashSet::new();

    let exceptions = pe
        .get_data_directory(ImageDirectoryEntry::Exception)
        .unwrap();

    if exceptions.virtual_address.0 == 0 || exceptions.size == 0 {
        return results;
    }

    let offset = pe
        .translate(PETranslation::Memory(exceptions.virtual_address))
        .unwrap();
    let size = exceptions.size as usize / size_of::<RuntimeFunction>();
    let functions = pe.get_slice_ref::<RuntimeFunction>(offset, size).unwrap();

    for rf in functions {
        results.insert(rf.begin_address);
        results.insert(rf.end_address);
    }

    results
}
