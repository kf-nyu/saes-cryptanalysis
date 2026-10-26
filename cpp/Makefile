CXX ?= clang++
CXXFLAGS ?= -O3 -flto -std=c++17 -pthread
TBB_PREFIX ?= /opt/homebrew
TBB_CFLAGS ?= -I$(TBB_PREFIX)/include
TBB_LIBS ?= -L$(TBB_PREFIX)/lib -ltbb

.PHONY: all cpu gpu clean

all: cpu gpu

cpu: cpu/saes_cpu

cpu/saes_cpu: cpu/cpu_main.cpp cpu/saes.hpp
	$(CXX) $(CXXFLAGS) $(TBB_CFLAGS) -o cpu/saes_cpu cpu/cpu_main.cpp $(TBB_LIBS)

gpu: metal/saes_gpu

metal/saes_gpu: metal/gpu_main.mm ../metal/saes.metal
	$(CXX) $(CXXFLAGS) -fobjc-arc -framework Metal -framework Foundation -o metal/saes_gpu metal/gpu_main.mm

clean:
	rm -f cpu/saes_cpu metal/saes_gpu
