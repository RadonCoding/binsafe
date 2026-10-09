use iced_x86::code_asm::{
    byte_ptr, dword_ptr, eax, ptr, r12, r13, r8, r8d, r9, r9b, r9d, r9w, rax, word_ptr, xmm0, xmm1,
    ymm0, ymm1,
};

use crate::{
    runtime::Runtime,
    vm::{
        bytecode::VMReg,
        utils::{self, scratch},
    },
};

pub fn with_width(
    rt: &mut Runtime,
    sse: impl FnOnce(&mut Runtime) + 'static,
    avx: impl FnOnce(&mut Runtime) + 'static,
) {
    let mut epilogue = rt.asm.create_label();

    // eax -> width
    utils::bytecode::read_byte_zx(rt, r13, eax);

    utils::width::dispatch(
        rt,
        rax,
        &mut epilogue,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(Box::new(|rt| {
            // load xmm1
            scratch::load_128(rt, r12, xmm1);
            // load xmm0
            scratch::load_128(rt, r12, xmm0);
            sse(rt);
            // store xmm0
            scratch::store_128(rt, r12, xmm0);
        })),
        Some(Box::new(|rt| {
            // load ymm1
            scratch::load_256(rt, r12, ymm1);
            // load ymm0
            scratch::load_256(rt, r12, ymm0);
            avx(rt);
            // store ymm0
            scratch::store_256(rt, r12, ymm0);
        })),
    );

    rt.asm.set_label(&mut epilogue).unwrap();
}

pub fn with_stride(
    rt: &mut Runtime,
    sse_32: impl FnOnce(&mut Runtime) + 'static,
    sse_64: impl FnOnce(&mut Runtime) + 'static,
    avx_32: impl FnOnce(&mut Runtime) + 'static,
    avx_64: impl FnOnce(&mut Runtime) + 'static,
) {
    let mut epilogue = rt.asm.create_label();

    // eax -> width
    utils::bytecode::read_byte_zx(rt, r13, eax);

    utils::width::dispatch(
        rt,
        rax,
        &mut epilogue,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(Box::new(move |rt| {
            let mut stride_epilogue = rt.asm.create_label();

            // r8d -> stride
            utils::bytecode::read_byte_zx(rt, r13, r8d);

            // load xmm1
            scratch::load_128(rt, r12, xmm1);
            // load xmm0
            scratch::load_128(rt, r12, xmm0);

            utils::width::dispatch(
                rt,
                r8,
                &mut stride_epilogue,
                Some(Box::new(move |rt| {
                    sse_64(rt);
                })),
                Some(Box::new(move |rt| {
                    sse_32(rt);
                })),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            );

            rt.asm.set_label(&mut stride_epilogue).unwrap();

            // store xmm0
            scratch::store_128(rt, r12, xmm0);
        })),
        Some(Box::new(move |rt| {
            let mut stride_epilogue = rt.asm.create_label();

            // r8d -> stride
            utils::bytecode::read_byte_zx(rt, r13, r8d);

            // load ymm1
            scratch::load_256(rt, r12, ymm1);
            // load ymm0
            scratch::load_256(rt, r12, ymm0);

            utils::width::dispatch(
                rt,
                r8,
                &mut stride_epilogue,
                Some(Box::new(move |rt| {
                    avx_64(rt);
                })),
                Some(Box::new(move |rt| {
                    avx_32(rt);
                })),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            );

            rt.asm.set_label(&mut stride_epilogue).unwrap();

            // store ymm0
            scratch::store_256(rt, r12, ymm0);
        })),
    );

    rt.asm.set_label(&mut epilogue).unwrap();
}

pub fn with_precision(
    rt: &mut Runtime,
    sse_int_8: impl FnOnce(&mut Runtime) + 'static,
    sse_int_16: impl FnOnce(&mut Runtime) + 'static,
    sse_int_32: impl FnOnce(&mut Runtime) + 'static,
    sse_int_64: impl FnOnce(&mut Runtime) + 'static,
    sse_float_8: impl FnOnce(&mut Runtime) + 'static,
    sse_float_16: impl FnOnce(&mut Runtime) + 'static,
    sse_float_32: impl FnOnce(&mut Runtime) + 'static,
    sse_float_64: impl FnOnce(&mut Runtime) + 'static,
    avx_int_8: impl FnOnce(&mut Runtime) + 'static,
    avx_int_16: impl FnOnce(&mut Runtime) + 'static,
    avx_int_32: impl FnOnce(&mut Runtime) + 'static,
    avx_int_64: impl FnOnce(&mut Runtime) + 'static,
    avx_float_8: impl FnOnce(&mut Runtime) + 'static,
    avx_float_16: impl FnOnce(&mut Runtime) + 'static,
    avx_float_32: impl FnOnce(&mut Runtime) + 'static,
    avx_float_64: impl FnOnce(&mut Runtime) + 'static,
) {
    let mut epilogue = rt.asm.create_label();

    // eax -> width
    utils::bytecode::read_byte_zx(rt, r13, eax);

    utils::width::dispatch(
        rt,
        rax,
        &mut epilogue,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(Box::new(move |rt| {
            let mut stride_epilogue = rt.asm.create_label();
            let mut precision_epilogue = rt.asm.create_label();

            // r8d -> stride
            utils::bytecode::read_byte_zx(rt, r13, r8d);

            // r9d -> precision
            utils::bytecode::read_byte_zx(rt, r13, r9d);

            // load xmm1
            scratch::load_128(rt, r12, xmm1);
            // load xmm0
            scratch::load_128(rt, r12, xmm0);

            utils::width::dispatch(
                rt,
                r8,
                &mut stride_epilogue,
                Some(Box::new(move |rt| {
                    utils::precision::dispatch(
                        rt,
                        r9,
                        &mut precision_epilogue,
                        Some(Box::new(|rt| {
                            sse_int_64(rt);
                        })),
                        Some(Box::new(|rt| {
                            sse_float_64(rt);
                        })),
                    );
                })),
                Some(Box::new(move |rt| {
                    utils::precision::dispatch(
                        rt,
                        r9,
                        &mut precision_epilogue,
                        Some(Box::new(|rt| {
                            sse_int_32(rt);
                        })),
                        Some(Box::new(|rt| {
                            sse_float_32(rt);
                        })),
                    );
                })),
                None,
                Some(Box::new(move |rt| {
                    utils::precision::dispatch(
                        rt,
                        r9,
                        &mut precision_epilogue,
                        Some(Box::new(|rt| {
                            sse_int_16(rt);
                        })),
                        Some(Box::new(|rt| {
                            sse_float_16(rt);
                        })),
                    );
                })),
                None,
                Some(Box::new(move |rt| {
                    utils::precision::dispatch(
                        rt,
                        r9,
                        &mut precision_epilogue,
                        Some(Box::new(|rt| {
                            sse_int_8(rt);
                        })),
                        Some(Box::new(|rt| {
                            sse_float_8(rt);
                        })),
                    );
                })),
                None,
                None,
                None,
                None,
                None,
                None,
            );

            rt.asm.set_label(&mut precision_epilogue).unwrap();

            // store xmm0
            scratch::store_128(rt, r12, xmm0);

            rt.asm.set_label(&mut stride_epilogue).unwrap();
        })),
        Some(Box::new(move |rt| {
            let mut stride_epilogue = rt.asm.create_label();
            let mut precision_epilogue = rt.asm.create_label();

            // r8d -> stride
            utils::bytecode::read_byte_zx(rt, r13, r8d);

            // r9d -> precision
            utils::bytecode::read_byte_zx(rt, r13, r9d);

            // load ymm1
            scratch::load_256(rt, r12, ymm1);
            // load ymm0
            scratch::load_256(rt, r12, ymm0);

            utils::width::dispatch(
                rt,
                r8,
                &mut stride_epilogue,
                Some(Box::new(move |rt| {
                    utils::precision::dispatch(
                        rt,
                        r9,
                        &mut precision_epilogue,
                        Some(Box::new(|rt| {
                            avx_int_64(rt);
                        })),
                        Some(Box::new(|rt| {
                            avx_float_64(rt);
                        })),
                    );
                })),
                Some(Box::new(move |rt| {
                    utils::precision::dispatch(
                        rt,
                        r9,
                        &mut precision_epilogue,
                        Some(Box::new(|rt| {
                            avx_int_32(rt);
                        })),
                        Some(Box::new(|rt| {
                            avx_float_32(rt);
                        })),
                    );
                })),
                None,
                Some(Box::new(move |rt| {
                    utils::precision::dispatch(
                        rt,
                        r9,
                        &mut precision_epilogue,
                        Some(Box::new(|rt| {
                            avx_int_16(rt);
                        })),
                        Some(Box::new(|rt| {
                            avx_float_16(rt);
                        })),
                    );
                })),
                None,
                Some(Box::new(move |rt| {
                    utils::precision::dispatch(
                        rt,
                        r9,
                        &mut precision_epilogue,
                        Some(Box::new(|rt| {
                            avx_int_8(rt);
                        })),
                        Some(Box::new(|rt| {
                            avx_float_8(rt);
                        })),
                    );
                })),
                None,
                None,
                None,
                None,
                None,
                None,
            );

            rt.asm.set_label(&mut precision_epilogue).unwrap();

            // store ymm0
            scratch::store_256(rt, r12, ymm0);

            rt.asm.set_label(&mut stride_epilogue).unwrap();
        })),
    );

    rt.asm.set_label(&mut epilogue).unwrap();
}

pub fn with_extension(
    rt: &mut Runtime,
    sse_float_64: impl FnOnce(&mut Runtime) + 'static,
    sse_int_32: impl FnOnce(&mut Runtime) + 'static,
    sse_float_32: impl FnOnce(&mut Runtime) + 'static,
    sse_int_h16: impl FnOnce(&mut Runtime) + 'static,
    sse_int_l16: impl FnOnce(&mut Runtime) + 'static,
    avx_float_64: impl FnOnce(&mut Runtime) + 'static,
    avx_int_32: impl FnOnce(&mut Runtime) + 'static,
    avx_float_32: impl FnOnce(&mut Runtime) + 'static,
    avx_int_h16: impl FnOnce(&mut Runtime) + 'static,
    avx_int_l16: impl FnOnce(&mut Runtime) + 'static,
) {
    let mut epilogue = rt.asm.create_label();

    // eax -> width
    utils::bytecode::read_byte_zx(rt, r13, eax);

    utils::width::dispatch(
        rt,
        rax,
        &mut epilogue,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(Box::new(move |rt| {
            let mut stride_epilogue = rt.asm.create_label();
            let mut precision_epilogue = rt.asm.create_label();

            // r8d -> stride
            utils::bytecode::read_byte_zx(rt, r13, r8d);

            // r9d -> precision
            utils::bytecode::read_byte_zx(rt, r13, r9d);

            // load xmm1
            scratch::load_128(rt, r12, xmm1);
            // load xmm0
            scratch::load_128(rt, r12, xmm0);

            utils::width::dispatch(
                rt,
                r8,
                &mut stride_epilogue,
                Some(Box::new(move |rt| {
                    utils::precision::dispatch(
                        rt,
                        r9,
                        &mut precision_epilogue,
                        None,
                        Some(Box::new(|rt| {
                            sse_float_64(rt);
                        })),
                    );
                })),
                Some(Box::new(move |rt| {
                    utils::precision::dispatch(
                        rt,
                        r9,
                        &mut precision_epilogue,
                        Some(Box::new(|rt| {
                            sse_int_32(rt);
                        })),
                        Some(Box::new(|rt| {
                            sse_float_32(rt);
                        })),
                    );
                })),
                Some(Box::new(move |rt| {
                    utils::precision::dispatch(
                        rt,
                        r9,
                        &mut precision_epilogue,
                        Some(Box::new(|rt| {
                            sse_int_h16(rt);
                        })),
                        None,
                    );
                })),
                Some(Box::new(move |rt| {
                    utils::precision::dispatch(
                        rt,
                        r9,
                        &mut precision_epilogue,
                        Some(Box::new(|rt| {
                            sse_int_l16(rt);
                        })),
                        None,
                    );
                })),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            );

            rt.asm.set_label(&mut precision_epilogue).unwrap();

            // store xmm0
            scratch::store_128(rt, r12, xmm0);

            rt.asm.set_label(&mut stride_epilogue).unwrap();
        })),
        Some(Box::new(move |rt| {
            let mut stride_epilogue = rt.asm.create_label();
            let mut precision_epilogue = rt.asm.create_label();

            // r8d -> stride
            utils::bytecode::read_byte_zx(rt, r13, r8d);

            // r9d -> precision
            utils::bytecode::read_byte_zx(rt, r13, r9d);

            // load ymm1
            scratch::load_256(rt, r12, ymm1);
            // load ymm0
            scratch::load_256(rt, r12, ymm0);

            utils::width::dispatch(
                rt,
                r8,
                &mut stride_epilogue,
                Some(Box::new(move |rt| {
                    utils::precision::dispatch(
                        rt,
                        r9,
                        &mut precision_epilogue,
                        None,
                        Some(Box::new(|rt| {
                            avx_float_64(rt);
                        })),
                    );
                })),
                Some(Box::new(move |rt| {
                    utils::precision::dispatch(
                        rt,
                        r9,
                        &mut precision_epilogue,
                        Some(Box::new(|rt| {
                            avx_int_32(rt);
                        })),
                        Some(Box::new(|rt| {
                            avx_float_32(rt);
                        })),
                    );
                })),
                Some(Box::new(move |rt| {
                    utils::precision::dispatch(
                        rt,
                        r9,
                        &mut precision_epilogue,
                        Some(Box::new(|rt| {
                            avx_int_h16(rt);
                        })),
                        None,
                    );
                })),
                Some(Box::new(move |rt| {
                    utils::precision::dispatch(
                        rt,
                        r9,
                        &mut precision_epilogue,
                        Some(Box::new(|rt| {
                            avx_int_l16(rt);
                        })),
                        None,
                    );
                })),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            );

            rt.asm.set_label(&mut precision_epilogue).unwrap();

            // store ymm0
            scratch::store_256(rt, r12, ymm0);

            rt.asm.set_label(&mut stride_epilogue).unwrap();
        })),
    );

    rt.asm.set_label(&mut epilogue).unwrap();
}

pub fn byte_mask(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    utils::bytecode::read_byte_zx(rt, r13, eax);

    utils::width::dispatch(
        rt,
        rax,
        &mut epilogue,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(Box::new(|rt| {
            scratch::load_128(rt, r12, xmm0);
            rt.asm.pmovmskb(r8d, xmm0).unwrap();
            scratch::store(rt, r12, r8);
        })),
        Some(Box::new(|rt| {
            scratch::load_256(rt, r12, ymm0);
            rt.asm.vpmovmskb(r8d, ymm0).unwrap();
            scratch::store(rt, r12, r8);
        })),
    );

    rt.asm.set_label(&mut epilogue).unwrap();
}

pub fn load_vector(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    utils::bytecode::read_byte_zx(rt, r13, r8d);
    utils::bytecode::read_byte_zx(rt, r13, r9d);

    rt.asm.shl(r9, 0x5).unwrap();

    utils::register::load(rt, r12, rax, VMReg::VVector);

    utils::width::dispatch(
        rt,
        r8,
        &mut epilogue,
        Some(Box::new(|rt| {
            rt.asm.mov(rax, ptr(rax + r9)).unwrap();
            scratch::store(rt, r12, rax);
        })),
        Some(Box::new(|rt| {
            rt.asm.mov(eax, ptr(rax + r9)).unwrap();
            scratch::store(rt, r12, rax);
        })),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(Box::new(|rt| {
            rt.asm.movups(xmm0, ptr(rax + r9)).unwrap();
            scratch::store_128(rt, r12, xmm0);
        })),
        Some(Box::new(|rt| {
            rt.asm.vmovups(ymm0, ptr(rax + r9)).unwrap();
            scratch::store_256(rt, r12, ymm0);
        })),
    );

    rt.asm.set_label(&mut epilogue).unwrap();
}

pub fn store_merge(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    utils::bytecode::read_byte_zx(rt, r13, r8d);
    utils::bytecode::read_byte_zx(rt, r13, r9d);

    rt.asm.shl(r9, 0x5).unwrap();

    utils::register::load(rt, r12, rax, VMReg::VVector);

    utils::width::dispatch(
        rt,
        r8,
        &mut epilogue,
        Some(Box::new(|rt| {
            scratch::load(rt, r12, r8);
            rt.asm.mov(ptr(rax + r9), r8).unwrap();
        })),
        Some(Box::new(|rt| {
            scratch::load(rt, r12, r8);
            rt.asm.mov(ptr(rax + r9), r8d).unwrap();
        })),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(Box::new(|rt| {
            scratch::load_128(rt, r12, xmm0);
            rt.asm.movups(ptr(rax + r9), xmm0).unwrap();
        })),
        Some(Box::new(|rt| {
            scratch::load_256(rt, r12, ymm0);
            rt.asm.vmovups(ptr(rax + r9), ymm0).unwrap();
        })),
    );

    rt.asm.set_label(&mut epilogue).unwrap();
}

pub fn store_extend(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    utils::bytecode::read_byte_zx(rt, r13, r8d);
    utils::bytecode::read_byte_zx(rt, r13, r9d);

    rt.asm.shl(r9, 0x5).unwrap();

    utils::register::load(rt, r12, rax, VMReg::VVector);

    utils::width::dispatch(
        rt,
        r8,
        &mut epilogue,
        Some(Box::new(|rt| {
            rt.asm.vmovups(ymm0, ptr(rax + r9)).unwrap();
            scratch::load(rt, r12, r8);
            rt.asm.movq(xmm0, r8).unwrap();
            rt.asm.vmovups(ptr(rax + r9), ymm0).unwrap();
        })),
        Some(Box::new(|rt| {
            rt.asm.vmovups(ymm0, ptr(rax + r9)).unwrap();
            scratch::load(rt, r12, r8);
            rt.asm.movd(xmm0, r8d).unwrap();
            rt.asm.vmovups(ptr(rax + r9), ymm0).unwrap();
        })),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(Box::new(|rt| {
            scratch::load_128(rt, r12, xmm0);
            rt.asm.vmovaps(xmm0, xmm0).unwrap();
            rt.asm.vmovups(ptr(rax + r9), ymm0).unwrap();
        })),
        Some(Box::new(|rt| {
            scratch::load_256(rt, r12, ymm0);
            rt.asm.vmovups(ptr(rax + r9), ymm0).unwrap();
        })),
    );

    rt.asm.set_label(&mut epilogue).unwrap();
}

pub fn load_memory(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    utils::bytecode::read_byte_zx(rt, r13, eax);

    scratch::load(rt, r12, r8);

    utils::width::dispatch(
        rt,
        rax,
        &mut epilogue,
        Some(Box::new(|rt| {
            rt.asm.mov(r9, ptr(r8)).unwrap();
            scratch::store(rt, r12, r9);
        })),
        Some(Box::new(|rt| {
            rt.asm.mov(r9d, ptr(r8)).unwrap();
            scratch::store(rt, r12, r9);
        })),
        None,
        Some(Box::new(|rt| {
            rt.asm.movzx(r9, word_ptr(r8)).unwrap();
            scratch::store(rt, r12, r9);
        })),
        Some(Box::new(|rt| {
            rt.asm.movzx(r9, byte_ptr(r8)).unwrap();
            scratch::store(rt, r12, r9);
        })),
        Some(Box::new(|rt| {
            rt.asm.movzx(r9, byte_ptr(r8)).unwrap();
            scratch::store(rt, r12, r9);
        })),
        Some(Box::new(|rt| {
            rt.asm.mov(r9, ptr(r8)).unwrap();
            scratch::store(rt, r12, r9);
        })),
        Some(Box::new(|rt| {
            rt.asm.movsxd(r9, dword_ptr(r8)).unwrap();
            scratch::store(rt, r12, r9);
        })),
        Some(Box::new(|rt| {
            rt.asm.movsx(r9, word_ptr(r8)).unwrap();
            scratch::store(rt, r12, r9);
        })),
        Some(Box::new(|rt| {
            rt.asm.movsx(r9, byte_ptr(r8)).unwrap();
            scratch::store(rt, r12, r9);
        })),
        Some(Box::new(|rt| {
            rt.asm.movups(xmm0, ptr(r8)).unwrap();
            scratch::store_128(rt, r12, xmm0);
        })),
        Some(Box::new(|rt| {
            rt.asm.vmovups(ymm0, ptr(r8)).unwrap();
            scratch::store_256(rt, r12, ymm0);
        })),
    );

    rt.asm.set_label(&mut epilogue).unwrap();
}

pub fn store_memory(rt: &mut Runtime) {
    let mut epilogue = rt.asm.create_label();

    utils::bytecode::read_byte_zx(rt, r13, eax);

    scratch::load(rt, r12, r8);

    utils::width::dispatch(
        rt,
        rax,
        &mut epilogue,
        Some(Box::new(|rt| {
            scratch::load(rt, r12, r9);
            rt.asm.mov(ptr(r8), r9).unwrap();
        })),
        Some(Box::new(|rt| {
            scratch::load(rt, r12, r9);
            rt.asm.mov(ptr(r8), r9d).unwrap();
        })),
        None,
        Some(Box::new(|rt| {
            scratch::load(rt, r12, r9);
            rt.asm.mov(ptr(r8), r9w).unwrap();
        })),
        None,
        Some(Box::new(|rt| {
            scratch::load(rt, r12, r9);
            rt.asm.mov(ptr(r8), r9b).unwrap();
        })),
        None,
        None,
        None,
        None,
        Some(Box::new(|rt| {
            scratch::load_128(rt, r12, xmm0);
            rt.asm.movups(ptr(r8), xmm0).unwrap();
        })),
        Some(Box::new(|rt| {
            scratch::load_256(rt, r12, ymm0);
            rt.asm.vmovups(ptr(r8), ymm0).unwrap();
        })),
    );

    rt.asm.set_label(&mut epilogue).unwrap();
}
