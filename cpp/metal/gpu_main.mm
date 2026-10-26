// S-AES 2^16 and Double S-AES 2^32 on GPU (Metal). Host only; kernel is metal/saes.metal.

#import <Foundation/Foundation.h>
#import <Metal/Metal.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>

struct Params {
    uint32_t p;
    uint32_t c;
};

struct OutCpu {
    uint32_t hits;
    uint32_t found_packed;
};

static std::string dirname_of(const char* path) {
    std::string s(path ? path : ".");
    auto slash = s.find_last_of('/');
    if (slash == std::string::npos) {
        return ".";
    }
    return s.substr(0, slash);
}

static NSString* find_metal_source(const char* argv0) {
    NSFileManager* fm = [NSFileManager defaultManager];
    NSMutableArray<NSString*>* candidates = [NSMutableArray array];
    std::string dir = dirname_of(argv0);
    [candidates addObject:@"../../metal/saes.metal"];
    [candidates addObject:@"../metal/saes.metal"];
    [candidates addObject:@"./metal/saes.metal"];
    [candidates addObject:[NSString stringWithUTF8String:(dir + "/../../metal/saes.metal").c_str()]];
    [candidates addObject:[NSString stringWithUTF8String:(dir + "/../metal/saes.metal").c_str()]];
    for (NSString* path in candidates) {
        if ([fm fileExistsAtPath:path]) {
            return path;
        }
    }
    return nil;
}

static OutCpu encode_and_wait(id<MTLDevice> device, id<MTLCommandQueue> queue,
                              id<MTLComputePipelineState> pipe, id<MTLBuffer> param_buf,
                              id<MTLBuffer> out_buf) {
    {
        uint32_t zeros[2] = {0, 0};
        memcpy(out_buf.contents, zeros, sizeof(zeros));
    }
    id<MTLCommandBuffer> cmd = [queue commandBuffer];
    id<MTLComputeCommandEncoder> enc = [cmd computeCommandEncoder];
    [enc setComputePipelineState:pipe];
    [enc setBuffer:param_buf offset:0 atIndex:0];
    [enc setBuffer:out_buf offset:0 atIndex:1];
    MTLSize grid = MTLSizeMake(65536, 1, 1);
    NSUInteger w = pipe.maxTotalThreadsPerThreadgroup;
    if (w > 256) {
        w = 256;
    }
    MTLSize group = MTLSizeMake(w, 1, 1);
    [enc dispatchThreads:grid threadsPerThreadgroup:group];
    [enc endEncoding];
    [cmd commit];
    [cmd waitUntilCompleted];
    OutCpu out{};
    memcpy(&out, out_buf.contents, sizeof(out));
    return out;
}

int main(int argc, const char** argv) {
    const uint32_t p = 0x6F6B;
    const uint32_t k = 0xA73B;
    const uint32_t c_saes = 0x0738;
    const uint32_t ka = 0xA73B;
    const uint32_t kb = 0x1337;
    const uint32_t c_double = 0xD62C;

    id<MTLDevice> device = MTLCreateSystemDefaultDevice();
    if (!device) {
        std::fprintf(stderr, "no Metal device\n");
        return 1;
    }
    NSString* metal_path = find_metal_source(argc > 0 ? argv[0] : ".");
    if (!metal_path) {
        std::fprintf(stderr, "metal/saes.metal not found (run from cpp/ or repo root)\n");
        return 1;
    }
    NSError* err = nil;
    NSString* src = [NSString stringWithContentsOfFile:metal_path
                                              encoding:NSUTF8StringEncoding
                                                 error:&err];
    if (!src) {
        std::fprintf(stderr, "read %s: %s\n", metal_path.UTF8String,
                     err.localizedDescription.UTF8String);
        return 1;
    }
    id<MTLLibrary> lib = [device newLibraryWithSource:src options:nil error:&err];
    if (!lib) {
        std::fprintf(stderr, "Metal compile: %s\n", err.localizedDescription.UTF8String);
        return 1;
    }
    id<MTLFunction> saes_fn = [lib newFunctionWithName:@"exhaustive_saes"];
    id<MTLFunction> double_fn = [lib newFunctionWithName:@"exhaustive"];
    id<MTLComputePipelineState> saes_pipe = [device newComputePipelineStateWithFunction:saes_fn
                                                                                  error:&err];
    id<MTLComputePipelineState> double_pipe =
        [device newComputePipelineStateWithFunction:double_fn error:&err];
    if (!saes_pipe || !double_pipe) {
        std::fprintf(stderr, "pipeline: %s\n", err.localizedDescription.UTF8String);
        return 1;
    }
    id<MTLCommandQueue> queue = [device newCommandQueue];
    id<MTLBuffer> param_buf = [device newBufferWithLength:sizeof(Params)
                                                  options:MTLResourceStorageModeShared];
    id<MTLBuffer> out_buf = [device newBufferWithLength:sizeof(OutCpu)
                                                options:MTLResourceStorageModeShared];

    std::printf("S-AES and Double S-AES (C++ + GPU / Metal)\n");
    std::printf("  adapter  %s\n", device.name.UTF8String);
    std::printf("  S-AES [2]     P=%04X  K=%04X  C=%04X\n", p, k, c_saes);
    std::printf("  Double S-AES  P=%04X  KA=%04X  KB=%04X  C=%04X\n\n", p, ka, kb, c_double);

    auto* params = reinterpret_cast<Params*>(param_buf.contents);
    params->p = p;
    params->c = c_saes;
    encode_and_wait(device, queue, saes_pipe, param_buf, out_buf);
    auto t0 = std::chrono::steady_clock::now();
    OutCpu saes_out = encode_and_wait(device, queue, saes_pipe, param_buf, out_buf);
    double saes_s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();

    std::printf("S-AES exhaustive FULL 2^16 on GPU\n");
    std::printf("  hits on this (P,C)   %u\n", saes_out.hits);
    std::printf("  last packed key      %04X\n", saes_out.found_packed);
    std::printf("  published K seen     %s\n", saes_out.hits > 0 ? "true" : "false");
    std::printf("  time                 %.6f s\n", saes_s);
    std::printf("  per trial            %.3f ns\n\n", (saes_s / 65536.0) * 1e9);

    params->p = p;
    params->c = c_double;
    encode_and_wait(device, queue, double_pipe, param_buf, out_buf);
    t0 = std::chrono::steady_clock::now();
    OutCpu double_out = encode_and_wait(device, queue, double_pipe, param_buf, out_buf);
    double double_s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();

    uint32_t found_ka = double_out.found_packed >> 16;
    uint32_t found_kb = double_out.found_packed & 0xFFFF;
    std::printf("Double S-AES exhaustive FULL 2^32 on GPU\n");
    std::printf("  hits on this (P,C)   %u\n", double_out.hits);
    std::printf("  last packed key      KA=%04X  KB=%04X\n", found_ka, found_kb);
    std::printf("  true key seen        %s\n", double_out.hits > 0 ? "true" : "false");
    std::printf("  time                 %.4f s\n", double_s);
    std::printf("  per trial            %.3f ns\n\n", (double_s / static_cast<double>(1ull << 32)) * 1e9);

    std::printf("Compare (this GPU run)\n");
    std::printf("  S-AES 2^16              %.6f s\n", saes_s);
    std::printf("  Double exhaustive 2^32  %.4f s\n", double_s);
    std::printf("  2^32 / 2^16             %.0fx more trials\n",
                static_cast<double>(1ull << 32) / 65536.0);
    return 0;
}
