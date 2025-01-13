PWD=$(shell pwd)
BOLT:=$(PWD)/llvm-project/build/bin/llvm-bolt

# Add Path to the binary
# Eg. BINARY:=/path/to/clang-20
BINARY:=/path/to/binary
CMAKE:=/usr/local/bin/cmake
.PHONY: run

outline:
	$(BOLT) $(BINARY) --findsimbb=main --outlinesimbb=main -o $(PWD)/outlined.bolt

baseline:
	$(BOLT) $(BINARY) -o $(PWD)/baseline.bolt

build:
	mkdir -p $(PWD)/llvm-project/build
	cd $(PWD)/llvm-project/build && $(CMAKE) -G Ninja -DCMAKE_BUILD_TYPE=Release -DLLVM_TARGETS_TO_BUILD=X86 -DLLVM_ENABLE_PROJECTS="bolt" -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DLLVM_USE_LINKER=lld -DLLVM_ENABLE_RTTI=On -DLLVM_INCLUDE_TESTS=Off ../llvm

# 	Replace 64 with $(nproc)
	cd $(PWD)/llvm-project/build && ninja -j64


help:
	$(BOLT) --help-list-hidden