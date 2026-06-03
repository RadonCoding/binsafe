use iced_x86::code_asm::{eax, ptr, r8, rax, rcx, rdx};

use crate::{
    mapper::Mappable,
    runtime::{DataDef, FnDef, Runtime},
    vm::{bytecode::VMReg, utils},
};

pub mod cleanup;
pub mod crypt;
pub mod dispatch;
pub mod entry;
pub mod exit;
pub mod ginit;
pub mod registers;
pub mod tinit;
pub mod vectors;
pub mod veh;

pub fn initialize(rt: &mut Runtime) {
    // mov eax, [...]
    rt.asm
        .mov(eax, ptr(rt.data_labels[&DataDef::VmRegistersTlsIndex]))
        .unwrap();
    // mov rax, [0x1480 + rcx*8]
    rt.asm.mov(rax, ptr(0x1480 + rax * 8).gs()).unwrap();

    // lea rcx, [...]
    rt.asm
        .lea(rcx, ptr(rt.data_labels[&DataDef::Functions]))
        .unwrap();

    rt.with_chain(|rt| {
        // xor rdx, rdx
        rt.asm.xor(rdx, rdx).unwrap();

        for def in FnDef::VARIANTS {
            let key = rt.mark_as_encrypted(rt.func_labels[&def]);
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

            // add r8, [...]
            utils::vreg::reg_add(rt, rax, VMReg::VImage, r8);

            // mov [rcx + ...], r8
            rt.asm
                .mov(ptr(rcx + rt.mapper.index(*def) as i32 * 8), r8)
                .unwrap();
        }
    });

    // ret
    rt.asm.ret().unwrap();
}
