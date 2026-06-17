use iced_x86::code_asm::{eax, r12, r8, r8d, r9, r9d, rax, rcx, xmm0, xmm1, ymm0, ymm1};

use crate::{
    runtime::Runtime,
    vm::utils::{self, scratch},
};

pub fn with_width(
    rt: &mut Runtime,
    sse: impl FnOnce(&mut Runtime) + 'static,
    avx: impl FnOnce(&mut Runtime) + 'static,
) {
    let mut epilogue = rt.asm.create_label();

    // eax -> width
    utils::bytecode::read_byte_zx(rt, rcx, eax);

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
    {
        // mov rax, rcx
        rt.asm.mov(rax, rcx).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
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
    utils::bytecode::read_byte_zx(rt, rcx, eax);

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
            utils::bytecode::read_byte_zx(rt, rcx, r8d);

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
            utils::bytecode::read_byte_zx(rt, rcx, r8d);

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
    {
        // mov rax, rcx
        rt.asm.mov(rax, rcx).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
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
    utils::bytecode::read_byte_zx(rt, rcx, eax);

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
            utils::bytecode::read_byte_zx(rt, rcx, r8d);

            // r9d -> precision
            utils::bytecode::read_byte_zx(rt, rcx, r9d);

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
            utils::bytecode::read_byte_zx(rt, rcx, r8d);

            // r9d -> precision
            utils::bytecode::read_byte_zx(rt, rcx, r9d);

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
    {
        // mov rax, rcx
        rt.asm.mov(rax, rcx).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}

pub fn with_stride_extended(
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
    utils::bytecode::read_byte_zx(rt, rcx, eax);

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
            utils::bytecode::read_byte_zx(rt, rcx, r8d);

            // r9d -> precision
            utils::bytecode::read_byte_zx(rt, rcx, r9d);

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
            utils::bytecode::read_byte_zx(rt, rcx, r8d);

            // r9d -> precision
            utils::bytecode::read_byte_zx(rt, rcx, r9d);

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
    {
        // mov rax, rcx
        rt.asm.mov(rax, rcx).unwrap();
        // ret
        rt.asm.ret().unwrap();
    }
}
