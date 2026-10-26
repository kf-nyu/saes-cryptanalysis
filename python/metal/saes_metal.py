"""Python host for metal/saes.metal via PyObjC.

This is not a Python GPU kernel and it does not start cpp/metal/saes_gpu.
The S-AES work is in the Metal shader. Python only loads it and reads hits.
"""

from __future__ import annotations

import ctypes
import time
from pathlib import Path


class Params(ctypes.Structure):
    _fields_ = [("p", ctypes.c_uint32), ("c", ctypes.c_uint32)]


class OutCpu(ctypes.Structure):
    _fields_ = [("hits", ctypes.c_uint32), ("found_packed", ctypes.c_uint32)]


def _shader_path() -> Path:
    root = Path(__file__).resolve().parents[2]
    path = root / "metal" / "saes.metal"
    if not path.is_file():
        raise FileNotFoundError(path)
    return path


def _write_struct(buf, value) -> None:
    raw = ctypes.string_at(ctypes.addressof(value), ctypes.sizeof(value))
    dest = buf.contents()
    for i, byte in enumerate(raw):
        dest[i] = bytes((byte,))


def _read_out(buf) -> OutCpu:
    src = buf.contents()
    raw = b"".join(src[i] for i in range(ctypes.sizeof(OutCpu)))
    return OutCpu.from_buffer_copy(raw)


def encode_and_wait(queue, pipe, param_buf, out_buf) -> OutCpu:
    import Metal

    zeros = OutCpu(0, 0)
    _write_struct(out_buf, zeros)
    cmd = queue.commandBuffer()
    enc = cmd.computeCommandEncoder()
    enc.setComputePipelineState_(pipe)
    enc.setBuffer_offset_atIndex_(param_buf, 0, 0)
    enc.setBuffer_offset_atIndex_(out_buf, 0, 1)
    w = pipe.maxTotalThreadsPerThreadgroup()
    if w > 256:
        w = 256
    enc.dispatchThreads_threadsPerThreadgroup_(
        Metal.MTLSizeMake(65536, 1, 1),
        Metal.MTLSizeMake(w, 1, 1),
    )
    enc.endEncoding()
    cmd.commit()
    cmd.waitUntilCompleted()
    return _read_out(out_buf)


def main() -> None:
    try:
        import Metal
    except ImportError:
        print("PyObjC Metal is not installed.")
        print("  python3 -m venv python/.venv")
        print("  python/.venv/bin/pip install -r python/requirements-metal.txt")
        print("  python/.venv/bin/python python/saes_metal.py")
        raise SystemExit(1)

    p = 0x6F6B
    k = 0xA73B
    c_saes = 0x0738
    ka = 0xA73B
    kb = 0x1337
    c_double = 0xD62C

    device = Metal.MTLCreateSystemDefaultDevice()
    if device is None:
        raise SystemExit("no Metal device")

    src = _shader_path().read_text()
    options = Metal.MTLCompileOptions.alloc().init()
    lib, err = device.newLibraryWithSource_options_error_(src, options, None)
    if lib is None:
        raise SystemExit(f"Metal compile: {err}")

    saes_fn = lib.newFunctionWithName_("exhaustive_saes")
    double_fn = lib.newFunctionWithName_("exhaustive")
    saes_pipe, err = device.newComputePipelineStateWithFunction_error_(saes_fn, None)
    if saes_pipe is None:
        raise SystemExit(f"pipeline: {err}")
    double_pipe, err = device.newComputePipelineStateWithFunction_error_(double_fn, None)
    if double_pipe is None:
        raise SystemExit(f"pipeline: {err}")

    queue = device.newCommandQueue()
    param_buf = device.newBufferWithLength_options_(
        ctypes.sizeof(Params), Metal.MTLResourceStorageModeShared
    )
    out_buf = device.newBufferWithLength_options_(
        ctypes.sizeof(OutCpu), Metal.MTLResourceStorageModeShared
    )

    print("S-AES and Double S-AES (Python host + Metal shader)")
    print(f"  adapter  {device.name()}")
    print("  host     Python / PyObjC (not cpp/metal/saes_gpu)")
    print(f"  shader   {_shader_path()}")
    print(f"  S-AES [2]     P={p:04X}  K={k:04X}  C={c_saes:04X}")
    print(f"  Double S-AES  P={p:04X}  KA={ka:04X}  KB={kb:04X}  C={c_double:04X}")
    print()

    _write_struct(param_buf, Params(p, c_saes))
    encode_and_wait(queue, saes_pipe, param_buf, out_buf)
    t0 = time.perf_counter()
    saes_out = encode_and_wait(queue, saes_pipe, param_buf, out_buf)
    saes_s = time.perf_counter() - t0

    print("S-AES exhaustive FULL 2^16 on GPU")
    print(f"  hits on this (P,C)   {saes_out.hits}")
    print(f"  last packed key      {saes_out.found_packed:04X}")
    print(f"  published K seen     {saes_out.hits > 0}")
    print(f"  time                 {saes_s:.6f} s")
    print(f"  per trial            {(saes_s / 65536.0) * 1e9:.3f} ns")
    print()

    _write_struct(param_buf, Params(p, c_double))
    encode_and_wait(queue, double_pipe, param_buf, out_buf)
    t0 = time.perf_counter()
    double_out = encode_and_wait(queue, double_pipe, param_buf, out_buf)
    double_s = time.perf_counter() - t0

    found_ka = double_out.found_packed >> 16
    found_kb = double_out.found_packed & 0xFFFF
    print("Double S-AES exhaustive FULL 2^32 on GPU")
    print(f"  hits on this (P,C)   {double_out.hits}")
    print(f"  last packed key      KA={found_ka:04X}  KB={found_kb:04X}")
    print(f"  true key seen        {double_out.hits > 0}")
    print(f"  time                 {double_s:.4f} s")
    print(f"  per trial            {(double_s / (1 << 32)) * 1e9:.3f} ns")
    print()

    print("Compare (Python host + metal/saes.metal; kernel is not Python)")
    print(f"  S-AES 2^16              {saes_s:.6f} s")
    print(f"  Double exhaustive 2^32  {double_s:.4f} s")
    print(f"  2^32 / 2^16             {(1 << 32) / (1 << 16):.0f}x more trials")


if __name__ == "__main__":
    main()
