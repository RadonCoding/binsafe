use iced_x86::code_asm::{ptr, r8, rax, rcx, rdx};

use crate::{
    mapper::Mappable,
    runtime::{DataDef, FnDef, Runtime},
};

pub mod cleanup;
pub mod crypt;
pub mod dispatch;
pub mod entry;
pub mod exit;
pub mod ginit;
pub mod lookup;
pub mod registers;
pub mod tinit;
pub mod vectors;
pub mod veh;

// void (unsigned char*)
pub fn initialize(rt:  &mut Runtime) {
    // lea rax, [...]
    rt.asm
        .lea(rax, ptr(rt.data_labels[&DataDef::Functions]))
        .unwrap();

    rt.with_chain(|rt| {
        // xor rdx, rdx
        rt.asm.xor(rdx, rdx).unwrap();

        for def in FnDef::VARIANTS {
            let key = rt.mark_as_encrypted(rt.function_labels[&def]);
            // mov r8, ...
            rt.asm.mov(r8, 0x0u64).unwrap();
            // xor rdx, r8
            rt.asm.xor(rdx, r8).unwrap();
            // mov r8, ...
            rt.asm.mov(r8, key).unwrap();
            // xor rdx, r8
            rt.asm.xor(rdx, r8).unwrap();

            // mov r8, rdx
            rt.asm.mov(r8, rdx).unwrap();
            // add r8, rcx
            rt.asm.add(r8, rcx).unwrap();
            // mov [rax + ...], rdx
            rt.asm
                .mov(ptr(rax + rt.mapper.index(*def) as i32 * 8), r8)
                .unwrap();
        }
    });

    // ret
    rt.asm.ret().unwrap();
}
