//! S-AES 2^16 and Double S-AES 2^32 on GPU via native Metal (not wgpu).
//! Uses the shared kernel metal/saes.metal (same file as the C++ Metal host).

use metal::{CompileOptions, Device, MTLResourceOptions, MTLSize};
use std::time::Instant;

#[repr(C)]
#[derive(Clone, Copy)]
struct Params {
    p: u32,
    c: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct OutCpu {
    hits: u32,
    found_packed: u32,
}

fn encode_and_wait(
    queue: &metal::CommandQueue,
    pipe: &metal::ComputePipelineState,
    param_buf: &metal::Buffer,
    out_buf: &metal::Buffer,
) -> OutCpu {
    unsafe {
        let out = out_buf.contents() as *mut OutCpu;
        *out = OutCpu {
            hits: 0,
            found_packed: 0,
        };
    }

    let cmd = queue.new_command_buffer();
    let enc = cmd.new_compute_command_encoder();
    enc.set_compute_pipeline_state(pipe);
    enc.set_buffer(0, Some(param_buf), 0);
    enc.set_buffer(1, Some(out_buf), 0);
    let mut w = pipe.max_total_threads_per_threadgroup();
    if w > 256 {
        w = 256;
    }
    enc.dispatch_threads(
        MTLSize {
            width: 65536,
            height: 1,
            depth: 1,
        },
        MTLSize {
            width: w,
            height: 1,
            depth: 1,
        },
    );
    enc.end_encoding();
    cmd.commit();
    cmd.wait_until_completed();

    unsafe { *(out_buf.contents() as *const OutCpu) }
}

fn main() {
    let p = 0x6F6Bu32;
    let k = 0xA73Bu32;
    let c_saes = 0x0738u32;
    let ka = 0xA73Bu32;
    let kb = 0x1337u32;
    let c_double = 0xD62Cu32;

    let device = Device::system_default().expect("no Metal device");
    let src = include_str!("../../../metal/saes.metal");
    let lib = device
        .new_library_with_source(src, &CompileOptions::new())
        .expect("Metal compile");
    let saes_fn = lib
        .get_function("exhaustive_saes", None)
        .expect("exhaustive_saes");
    let double_fn = lib.get_function("exhaustive", None).expect("exhaustive");
    let saes_pipe = device
        .new_compute_pipeline_state_with_function(&saes_fn)
        .expect("saes pipeline");
    let double_pipe = device
        .new_compute_pipeline_state_with_function(&double_fn)
        .expect("double pipeline");
    let queue = device.new_command_queue();
    let param_buf = device.new_buffer(
        std::mem::size_of::<Params>() as u64,
        MTLResourceOptions::StorageModeShared,
    );
    let out_buf = device.new_buffer(
        std::mem::size_of::<OutCpu>() as u64,
        MTLResourceOptions::StorageModeShared,
    );

    println!("S-AES and Double S-AES (Rust + GPU / native Metal)");
    println!("  adapter  {}", device.name());
    println!("  S-AES [2]     P={p:04X}  K={k:04X}  C={c_saes:04X}");
    println!("  Double S-AES  P={p:04X}  KA={ka:04X}  KB={kb:04X}  C={c_double:04X}");
    println!();

    unsafe {
        *(param_buf.contents() as *mut Params) = Params { p, c: c_saes };
    }
    encode_and_wait(&queue, &saes_pipe, &param_buf, &out_buf);
    let t0 = Instant::now();
    let saes_out = encode_and_wait(&queue, &saes_pipe, &param_buf, &out_buf);
    let saes_s = t0.elapsed().as_secs_f64();

    println!("S-AES exhaustive FULL 2^16 on GPU");
    println!("  hits on this (P,C)   {}", saes_out.hits);
    println!("  last packed key      {:04X}", saes_out.found_packed);
    println!("  published K seen     {}", saes_out.hits > 0);
    println!("  time                 {saes_s:.6} s");
    println!(
        "  per trial            {:.3} ns",
        (saes_s / 65536.0) * 1e9
    );
    println!();

    unsafe {
        *(param_buf.contents() as *mut Params) = Params { p, c: c_double };
    }
    encode_and_wait(&queue, &double_pipe, &param_buf, &out_buf);
    let t1 = Instant::now();
    let double_out = encode_and_wait(&queue, &double_pipe, &param_buf, &out_buf);
    let double_s = t1.elapsed().as_secs_f64();

    let found_ka = double_out.found_packed >> 16;
    let found_kb = double_out.found_packed & 0xFFFF;
    println!("Double S-AES exhaustive FULL 2^32 on GPU");
    println!("  hits on this (P,C)   {}", double_out.hits);
    println!(
        "  last packed key      KA={found_ka:04X}  KB={found_kb:04X}"
    );
    println!("  true key seen        {}", double_out.hits > 0);
    println!("  time                 {double_s:.4} s");
    println!(
        "  per trial            {:.3} ns",
        (double_s / (1u64 << 32) as f64) * 1e9
    );
    println!();

    println!("Compare (this native Metal Rust run, not wgpu)");
    println!("  S-AES 2^16              {saes_s:.6} s");
    println!("  Double exhaustive 2^32  {double_s:.4} s");
    println!(
        "  2^32 / 2^16             {:.0}x more trials",
        (1u64 << 32) as f64 / 65536.0
    );
}
