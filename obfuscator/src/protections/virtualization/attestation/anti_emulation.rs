use crate::engine::Engine;
use crate::protections::virtualization::attestation::*;
use runtime::vm::bytecode::{Flag, VMReg};
use runtime::vm::encoders::Encode;

// CPUID.1:ECX[31]
const HYPERVISOR_PRESENT_BIT: u64 = 31;

const HYPERVISOR_VENDOR_LEAF: u32 = 0x4000_0000;

pub fn generate(engine: &mut Engine, expected: &mut u64) -> Vec<Box<dyn Encode>> {
    let mut b = Vec::<Box<dyn Encode>>::new();

    b.extend(cpuid(1, 0));
    b.extend(discard());
    b.extend(immediate(HYPERVISOR_PRESENT_BIT));
    b.extend(shr(None, None));
    b.extend(store_register(VMReg::R8));
    b.extend(discard());
    b.extend(discard());

    b.extend(cpuid(HYPERVISOR_VENDOR_LEAF, 0));
    b.extend(or(None, None));
    b.extend(or(None, None));
    b.extend(or(None, None));

    b.extend(immediate(1));
    b.extend(sub(None, None));
    b.extend(discard());
    b.extend(flag(Flag::Carry));

    b.extend(and(Some(VMReg::R8), None));

    b.extend(accumulate_immediate(engine, VMReg::Vp0, None, 0, expected));

    b
}
