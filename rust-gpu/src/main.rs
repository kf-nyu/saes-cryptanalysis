//! S-AES 2^16 and Double S-AES 2^32 exhaustive search on GPU (wgpu → Metal).

use std::time::Instant;

#[repr(C)]
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
struct Params {
    p: u32,
    c: u32,
}

#[repr(C)]
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
struct OutCpu {
    hits: u32,
    found_packed: u32,
}

fn main() {
    pollster::block_on(run());
}

async fn run() {
    let p = 0x6F6Bu32;
    let k = 0xA73Bu32;
    let c_saes = 0x0738u32;
    let ka = 0xA73Bu32;
    let kb = 0x1337u32;
    let c_double = 0xD62Cu32;

    let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor {
        backends: wgpu::Backends::METAL | wgpu::Backends::VULKAN | wgpu::Backends::DX12,
        ..Default::default()
    });
    let adapter = instance
        .request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: wgpu::PowerPreference::HighPerformance,
            compatible_surface: None,
            force_fallback_adapter: false,
        })
        .await
        .expect("no GPU adapter");
    let info = adapter.get_info();
    println!("S-AES and Double S-AES (Rust + GPU / wgpu)");
    println!("  adapter  {} ({:?})", info.name, info.backend);
    println!("  S-AES [2]     P={p:04X}  K={k:04X}  C={c_saes:04X}");
    println!("  Double S-AES  P={p:04X}  KA={ka:04X}  KB={kb:04X}  C={c_double:04X}");
    println!();

    let (device, queue) = adapter
        .request_device(&wgpu::DeviceDescriptor {
            label: Some("saes"),
            required_features: wgpu::Features::empty(),
            required_limits: wgpu::Limits::default(),
            memory_hints: wgpu::MemoryHints::Performance,
            trace: wgpu::Trace::Off,
        })
        .await
        .expect("request_device");

    let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
        label: Some("saes"),
        source: wgpu::ShaderSource::Wgsl(include_str!("shader.wgsl").into()),
    });

    let param_buf = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("params"),
        size: std::mem::size_of::<Params>() as u64,
        usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    let out_size = std::mem::size_of::<OutCpu>() as u64;
    let out_buf = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("out"),
        size: out_size,
        usage: wgpu::BufferUsages::STORAGE
            | wgpu::BufferUsages::COPY_SRC
            | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    let read_buf = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("read"),
        size: out_size,
        usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });

    let bgl = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
        label: Some("bgl"),
        entries: &[
            wgpu::BindGroupLayoutEntry {
                binding: 0,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Uniform,
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
            wgpu::BindGroupLayoutEntry {
                binding: 1,
                visibility: wgpu::ShaderStages::COMPUTE,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Storage { read_only: false },
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            },
        ],
    });
    let bind = device.create_bind_group(&wgpu::BindGroupDescriptor {
        label: Some("bg"),
        layout: &bgl,
        entries: &[
            wgpu::BindGroupEntry {
                binding: 0,
                resource: param_buf.as_entire_binding(),
            },
            wgpu::BindGroupEntry {
                binding: 1,
                resource: out_buf.as_entire_binding(),
            },
        ],
    });
    let layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
        label: Some("pl"),
        bind_group_layouts: &[&bgl],
        push_constant_ranges: &[],
    });
    let saes_pipe = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
        label: Some("saes"),
        layout: Some(&layout),
        module: &shader,
        entry_point: Some("exhaustive_saes"),
        compilation_options: Default::default(),
        cache: None,
    });
    let double_pipe = device.create_compute_pipeline(&wgpu::ComputePipelineDescriptor {
        label: Some("double"),
        layout: Some(&layout),
        module: &shader,
        entry_point: Some("exhaustive"),
        compilation_options: Default::default(),
        cache: None,
    });

    queue.write_buffer(&param_buf, 0, bytemuck::bytes_of(&Params { p, c: c_saes }));
    encode_and_wait(&device, &queue, &saes_pipe, &bind, &out_buf, &read_buf);
    let t0 = Instant::now();
    let saes_out = encode_and_wait(&device, &queue, &saes_pipe, &bind, &out_buf, &read_buf);
    let saes_s = t0.elapsed().as_secs_f64();

    println!("S-AES exhaustive FULL 2^16 on GPU");
    println!("  hits on this (P,C)   {}", saes_out.hits);
    println!("  last packed key      {:04X}", saes_out.found_packed);
    println!("  published K seen     {}", saes_out.hits > 0);
    println!("  time                 {saes_s:.6} s");
    println!(
        "  per trial            {:.3} ns",
        (saes_s / (1u64 << 16) as f64) * 1e9
    );
    println!();

    queue.write_buffer(
        &param_buf,
        0,
        bytemuck::bytes_of(&Params { p, c: c_double }),
    );
    encode_and_wait(&device, &queue, &double_pipe, &bind, &out_buf, &read_buf);
    let t1 = Instant::now();
    let double_out = encode_and_wait(&device, &queue, &double_pipe, &bind, &out_buf, &read_buf);
    let double_s = t1.elapsed().as_secs_f64();

    let found_ka = double_out.found_packed >> 16;
    let found_kb = double_out.found_packed & 0xFFFF;
    println!("Double S-AES exhaustive FULL 2^32 on GPU");
    println!("  hits on this (P,C)   {}", double_out.hits);
    println!("  last packed key      KA={found_ka:04X}  KB={found_kb:04X}");
    println!("  true key seen        {}", double_out.hits > 0);
    println!("  time                 {double_s:.4} s");
    println!(
        "  per trial            {:.3} ns",
        (double_s / (1u64 << 32) as f64) * 1e9
    );
    println!();

    println!("Compare (this GPU run)");
    println!("  S-AES 2^16              {saes_s:.6} s");
    println!("  Double exhaustive 2^32  {double_s:.4} s");
    println!(
        "  2^32 / 2^16             {:.0}x more trials",
        (1u64 << 32) as f64 / (1u64 << 16) as f64
    );
}

fn encode_and_wait(
    device: &wgpu::Device,
    queue: &wgpu::Queue,
    pipeline: &wgpu::ComputePipeline,
    bind: &wgpu::BindGroup,
    out_buf: &wgpu::Buffer,
    read_buf: &wgpu::Buffer,
) -> OutCpu {
    let mut enc = device.create_command_encoder(&wgpu::CommandEncoderDescriptor { label: None });
    enc.clear_buffer(out_buf, 0, None);
    {
        let mut pass = enc.begin_compute_pass(&wgpu::ComputePassDescriptor {
            label: Some("exh"),
            timestamp_writes: None,
        });
        pass.set_pipeline(pipeline);
        pass.set_bind_group(0, bind, &[]);
        pass.dispatch_workgroups(256, 1, 1); // 256*256 = 65536 threads
    }
    enc.clear_buffer(read_buf, 0, None);
    enc.copy_buffer_to_buffer(out_buf, 0, read_buf, 0, std::mem::size_of::<OutCpu>() as u64);
    queue.submit(Some(enc.finish()));

    let slice = read_buf.slice(..);
    let (tx, rx) = std::sync::mpsc::channel();
    slice.map_async(wgpu::MapMode::Read, move |r| tx.send(r).unwrap());
    device.poll(wgpu::PollType::Wait).unwrap();
    rx.recv().unwrap().unwrap();
    let data = slice.get_mapped_range();
    let out = *bytemuck::from_bytes::<OutCpu>(&data);
    drop(data);
    read_buf.unmap();
    out
}
