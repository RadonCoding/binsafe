use runtime::vm::bytecode::{VMReg, VMWidth};
use runtime::vm::encoders::load_immediate::LoadImmediate;
use runtime::vm::encoders::store_register::StoreRegister;
use runtime::vm::encoders::Encode;

pub fn generate(target: u64) -> Vec<Box<dyn Encode>> {
    vec![
        Box::new(LoadImmediate {
            width: VMWidth::Lower64,
            source: target.to_le_bytes().to_vec(),
        }),
        Box::new(StoreRegister {
            width: VMWidth::Lower64,
            destination: VMReg::VKey,
        }),
    ]
}
