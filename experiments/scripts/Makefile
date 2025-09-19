# --- Configuration ---
SHELL := /bin/bash
.ONESHELL:
.PHONY: all bootstrapped_clang instr_clang instr_clang_data fdo_clang data clean

# Base directory for LLVM source code
LLVM_SRC_DIR := $(shell cd ../../ ; pwd)

# Development directory where all builds are stored
DEV_DIR := $(shell mkdir -p ../../../ipra-run ; cd ../../../ipra-run ; pwd)

# Master list of all compiler build names. To add a new compiler, just add it here.
COMPILER_LIST := \
	bootstrapped_clang \
	instr_clang \
	fdo_clang \
	thinly_linked_fdo_clang \
	fully_linked_fdo_clang \
	ipra_fdo_clang \
	ipra_thinly_linked_fdo_clang \
	ipra_fully_linked_fdo_clang \
	preserve_none_fdo_clang

# Loop through the list and automatically define the _DIR and _SENTINEL variables.
$(foreach compiler, $(COMPILER_LIST), \
	$(eval $(shell echo $(compiler) | tr '[:lower:]' '[:upper:]' | sed 's/_CLANG$$//')_DIR := $(DEV_DIR)/$(compiler)) \
	$(eval $(shell echo $(compiler) | tr '[:lower:]' '[:upper:]' | sed 's/_CLANG$$//')_SENTINEL := $($(shell echo $(compiler) | tr '[:lower:]' '[:upper:]' | sed 's/_CLANG$$//')_DIR)/.completed) \
)

# Profile data directories and files
PROFILE_RAW_DIR := $(INSTR_DIR)/profiles
PROFILE_MERGED_FILE := $(INSTR_DIR)/clang.profdata

# Metrics file
METRICS_DIR := $(DEV_DIR)/metrics
FDO_LIVENESS_OUTPUT_DIR := $(METRICS_DIR)/fdo_liveness_output

# Number of parallel jobs to use for compilation
# Can reduce to nproc - 4 if system is under heavy load
JOBS := $(shell nproc)

# --- Helper Function (similar to log) ---
define log
	echo
	echo "--- $$(date '+%Y-%m-%d %H:%M:%S') ---"
	echo "--- $(1)"
	echo "-----------------------------------------------------"
endef

print-var:
	@echo $($(VARNAME))

# --- Main Targets ---

# Default target: build everything up to the FDO-optimized clang
all: bootstrapped_clang instr_clang instr_clang_data fdo_clang thinly_linked_fdo_clang ipra_fdo_clang ipra_thinly_linked_fdo_clang fully_linked_fdo_clang ipra_fully_linked_fdo_clang preserve_none_fdo_clang data ipra_data linked_data
	@$(MAKE) benchmark COMPILER=fdo_clang

experiments: ipra_fdo_clang ipra_thinly_linked_fdo_clang ipra_data
linked: thinly_linked_fdo_clang ipra_thinly_linked_fdo_clang fully_linked_fdo_clang ipra_fully_linked_fdo_clang

# Target 1: Build the initial, optimized 'bootstrapped_clang'
bootstrapped_clang: $(BOOTSTRAPPED_SENTINEL)
$(BOOTSTRAPPED_SENTINEL):
	$(call log,STEP 1: Building bootstrapped_clang (Release build with runtimes))
	cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(BOOTSTRAPPED_DIR)" \
	  -D CMAKE_BUILD_TYPE=Release \
	  -D LLVM_ENABLE_PROJECTS="clang;lld" \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_ENABLE_RUNTIMES="compiler-rt"
	ninja -j "$(JOBS)" -C "$(BOOTSTRAPPED_DIR)"
	@touch $@
	$(call log,✅ STEP 1: bootstrapped_clang built successfully.)

# Target 2: Build the instrumented 'instr_clang'
instr_clang: $(INSTR_SENTINEL)
$(INSTR_SENTINEL): $(BOOTSTRAPPED_SENTINEL)
	$(call log,STEP 2: Building instr_clang (Instrumented build))
	cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(INSTR_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
	  -D CMAKE_BUILD_TYPE=Release \
	  -D LLVM_ENABLE_PROJECTS="clang;lld" \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_BUILD_INSTRUMENTED=ON \
	  -D CMAKE_C_FLAGS="-fprofile-instr-generate" \
	  -D CMAKE_CXX_FLAGS="-fprofile-instr-generate" \
	  -D CMAKE_EXE_LINKER_FLAGS="-fprofile-instr-generate" \
	  -D CMAKE_SHARED_LINKER_FLAGS="-fprofile-instr-generate"
	ninja -j "$(JOBS)" -C "$(INSTR_DIR)"
	@touch $@
	$(call log,✅ STEP 2: instr_clang built successfully.)

# Target 3: Generate and merge profile data
instr_clang_data: $(PROFILE_MERGED_FILE)
$(PROFILE_MERGED_FILE): $(INSTR_SENTINEL)
	@$(call log,STEP 3: Generating profile data (.profraw files))
	@set -e; \
	rm -rf "$(PROFILE_RAW_DIR)"; \
	mkdir -p "$(PROFILE_RAW_DIR)"; \
	export LLVM_PROFILE_FILE="$(PROFILE_RAW_DIR)/clang-%p.profraw"; \
	TEMP_PROFILE_BUILD_DIR="$(DEV_DIR)/temp_profiling_build"; \
	cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$$TEMP_PROFILE_BUILD_DIR" \
	  -D CMAKE_C_COMPILER="$(INSTR_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(INSTR_DIR)/bin/clang++" \
	  -D CMAKE_BUILD_TYPE=Release \
	  -D LLVM_ENABLE_PROJECTS=clang \
	  -D LLVM_TARGETS_TO_BUILD=X86; \
	ninja -j "$(JOBS)" -C "$$TEMP_PROFILE_BUILD_DIR" llc; \
	rm -rf "$$TEMP_PROFILE_BUILD_DIR"; \
	$(call log,✅ STEP 3: Profile data generated in $(PROFILE_RAW_DIR)); \
	$(call log,STEP 4: Merging profile data); \
	"$(INSTR_DIR)/bin/llvm-profdata" merge -j "$(JOBS)" -o "$@" "$(PROFILE_RAW_DIR)"/*.profraw; \
	$(call log,✅ STEP 4: Merged profile data created at $@)

# Target 4: Build the final 'fdo_clang' with Profile-Guided Optimizations
fdo_clang: $(FDO_SENTINEL)
$(FDO_SENTINEL): $(BOOTSTRAPPED_SENTINEL) $(PROFILE_MERGED_FILE)
	@$(call log,STEP 5: Building fdo_clang (PGO-optimized build))
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(FDO_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
	  -D CMAKE_BUILD_TYPE=Release \
	  -D LLVM_ENABLE_PROJECTS=clang \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_PROFDATA_FILE="$(PROFILE_MERGED_FILE)"
	@ninja -j "$(JOBS)" -C "$(FDO_DIR)"
	@touch $@
	@$(call log,✅ STEP 5: fdo_clang built successfully.)

# NEW Target: Build the 'thinly_linked_fdo_clang' with PGO and ThinLTO
thinly_linked_fdo_clang: $(THINLY_LINKED_FDO_SENTINEL)
$(THINLY_LINKED_FDO_SENTINEL): $(BOOTSTRAPPED_SENTINEL) $(PROFILE_MERGED_FILE)
	@$(call log,STEP 5B: Building thinly_linked_fdo_clang (PGO + ThinLTO build))
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(THINLY_LINKED_FDO_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
	  -D CMAKE_BUILD_TYPE=Release \
	  -D LLVM_ENABLE_PROJECTS=clang \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_PROFDATA_FILE="$(PROFILE_MERGED_FILE)" \
	  -D LLVM_ENABLE_LTO=Thin \
	  -D LLVM_USE_LINKER=lld
	@ninja -j "$(JOBS)" -C "$(THINLY_LINKED_FDO_DIR)" && \
	touch $@ && \
	$(call log,✅ STEP 5B: thinly_linked_fdo_clang built successfully.)

# NEW Target: Build the 'thinly_linked_fdo_clang' with PGO and ThinLTO
fully_linked_fdo_clang: $(FULLY_LINKED_FDO_SENTINEL)
$(FULLY_LINKED_FDO_SENTINEL): $(BOOTSTRAPPED_SENTINEL) $(PROFILE_MERGED_FILE)
	@$(call log,STEP 5E: Building fully_linked_fdo_clang (PGO + FULLLTO build))
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(FULLY_LINKED_FDO_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
	  -D CMAKE_BUILD_TYPE=Release \
	  -D LLVM_ENABLE_PROJECTS=clang \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_PROFDATA_FILE="$(PROFILE_MERGED_FILE)" \
	  -D LLVM_ENABLE_LTO=Full \
	  -D LLVM_USE_LINKER=lld
	@ninja -j "$(JOBS)" -C "$(FULLY_LINKED_FDO_DIR)" && \
	touch $@ && \
	$(call log,✅ STEP 5E: fully_linked_fdo_clang built successfully.)

# NEW Target: Build the 'thinly_linked_fdo_clang' with PGO and ThinLTO
ipra_fully_linked_fdo_clang: $(IPRA_FULLY_LINKED_FDO_SENTINEL)
$(IPRA_FULLY_LINKED_FDO_SENTINEL): $(BOOTSTRAPPED_SENTINEL) $(PROFILE_MERGED_FILE)
	@$(call log,STEP 5F: Building ipra_fully_linked_fdo_clang (PGO + FULLLTO build))
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(IPRA_FULLY_LINKED_FDO_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
	  -D CMAKE_BUILD_TYPE=Release \
	  -D LLVM_ENABLE_PROJECTS=clang \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_PROFDATA_FILE="$(PROFILE_MERGED_FILE)" \
	  -D LLVM_ENABLE_LTO=Full \
	  -D LLVM_USE_LINKER=lld \
	  -D CMAKE_C_FLAGS="-mllvm -enable-ipra" \
	  -D CMAKE_CXX_FLAGS="-mllvm -enable-ipra" \
	  -D CMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld -Wl,-mllvm,-enable-ipra" \
	  -D CMAKE_SHARED_LINKER_FLAGS="-fuse-ld=lld -Wl,-mllvm,-enable-ipra" \
	  -D CMAKE_MODULE_LINKER_FLAGS="-fuse-ld=lld -Wl,-mllvm,-enable-ipra"
	@ninja -j "$(JOBS)" -C "$(IPRA_FULLY_LINKED_FDO_DIR)" && \
	touch $@ && \
	$(call log,✅ STEP 5F: ipra_fully_linked_fdo_clang built successfully.)

# NEW Target: Build 'ipra_fdo_clang' with PGO and the IPRA optimization.
ipra_fdo_clang: $(IPRA_FDO_SENTINEL)
$(IPRA_FDO_SENTINEL): $(BOOTSTRAPPED_SENTINEL) $(PROFILE_MERGED_FILE)
	@$(call log,STEP 5C: Building ipra_fdo_clang (PGO + IPRA build))
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(IPRA_FDO_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
	  -D CMAKE_BUILD_TYPE=Release \
	  -D LLVM_ENABLE_PROJECTS=clang \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_PROFDATA_FILE="$(PROFILE_MERGED_FILE)" \
	  -D CMAKE_C_FLAGS="-mllvm -enable-ipra" \
	  -D CMAKE_CXX_FLAGS="-mllvm -enable-ipra"
	@ninja -j "$(JOBS)" -C "$(IPRA_FDO_DIR)" && \
	touch $@ && \
	$(call log,✅ STEP 5C: ipra_fdo_clang built successfully.)

# NEW Target: Build 'ipra_thinly_linked_fdo_clang' with PGO, ThinLTO, and IPRA.
ipra_thinly_linked_fdo_clang: $(IPRA_THINLY_LINKED_FDO_SENTINEL)
$(IPRA_THINLY_LINKED_FDO_SENTINEL): $(BOOTSTRAPPED_SENTINEL) $(PROFILE_MERGED_FILE)
	@$(call log,STEP 5D: Building ipra_thinly_linked_fdo_clang (PGO + ThinLTO + IPRA build))
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(IPRA_THINLY_LINKED_FDO_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
	  -D CMAKE_BUILD_TYPE=Release \
	  -D LLVM_ENABLE_PROJECTS=clang \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_PROFDATA_FILE="$(PROFILE_MERGED_FILE)" \
	  -D LLVM_ENABLE_LTO=Thin \
	  -D LLVM_USE_LINKER=lld \
	  -D CMAKE_C_FLAGS="-mllvm -enable-ipra" \
	  -D CMAKE_CXX_FLAGS="-mllvm -enable-ipra" \
	  -D CMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld -Wl,-mllvm,-enable-ipra" \
	  -D CMAKE_SHARED_LINKER_FLAGS="-fuse-ld=lld -Wl,-mllvm,-enable-ipra" \
	  -D CMAKE_MODULE_LINKER_FLAGS="-fuse-ld=lld -Wl,-mllvm,-enable-ipra"
	@ninja -j "$(JOBS)" -C "$(IPRA_THINLY_LINKED_FDO_DIR)" && \
	touch $@ && \
	$(call log,✅ STEP 5D: ipra_thinly_linked_fdo_clang built successfully.)

# NEW Target: Build 'preserve_none_fdo_clang' with PGO and the PreserveNonePass optimization.
preserve_none_fdo_clang:
	@$(call log,STEP 5G: Building preserve_none_fdo_clang)
	@set -e; \
	# Define the path to the JSON profile locally for this target.
	PRESERVE_NONE_PROFILE="$(FDO_LIVENESS_OUTPUT_DIR)/liveness_profdata.json"; 
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(PRESERVE_NONE_FDO_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
	  -D CMAKE_BUILD_TYPE=Release \
	  -D LLVM_ENABLE_PROJECTS=clang \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_PROFDATA_FILE="$(PROFILE_MERGED_FILE)" \
      -D CMAKE_C_FLAGS="-mllvm -preserve-none-enable -mllvm -preserve-none-json=$${PRESERVE_NONE_PROFILE}" \
      -D CMAKE_CXX_FLAGS="-mllvm -preserve-none-enable -mllvm -preserve-none-json=$${PRESERVE_NONE_PROFILE}"
	@ninja -j "$(JOBS)" -C "$(PRESERVE_NONE_FDO_DIR)" && \
	touch $@ && \
	$(call log,✅ STEP 5G: preserve_none_fdo_clang built successfully.)

fdo_liveness_analysis: fdo_clang
	@$(call log,Collecting Liveness Data using fdo_clang)
	@mkdir -p "$(FDO_LIVENESS_OUTPUT_DIR)"
	@TEMP_LLD_BUILD_DIR="$(DEV_DIR)/temp_lld_for_liveness_analysis"
	@rm -rf "$$TEMP_LLD_BUILD_DIR"
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$$TEMP_LLD_BUILD_DIR" \
		-D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
		-D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
		-D CMAKE_BUILD_TYPE=Release \
		-D LLVM_ENABLE_PROJECTS=lld \
		-D LLVM_TARGETS_TO_BUILD=X86 \
		-D LLVM_PROFDATA_FILE="$(PROFILE_MERGED_FILE)" \
		-D CMAKE_CXX_FLAGS="-mllvm -enable-cs-reg-liveness-analysis -mllvm -cs-reg-liveness-analysis-output-dir=$(FDO_LIVENESS_OUTPUT_DIR)"
	@ninja -j "$(JOBS)" -C "$$TEMP_LLD_BUILD_DIR" lld
	@rm -rf "$$TEMP_LLD_BUILD_DIR"
	@$(call log,✅ Liveness Data collected in $(FDO_LIVENESS_OUTPUT_DIR))

# Usage: make benchmark COMPILER=<compiler_name> [BENCHMARK_RUNS=N]
benchmark:
	@if [ -z "$(COMPILER)" ]; then \
		echo "Error: You must specify which compiler to benchmark."; \
		echo "Usage: make benchmark COMPILER=<name>"; \
		exit 1; \
	fi

	@set -e; \
	\
	# Dynamically construct the variable names based on the COMPILER input.
	VAR_BASE_NAME=$$(echo $(COMPILER) | tr '[:lower:]' '[:upper:]' | sed 's/_CLANG$$//'); \
	SENTINEL_VAR_NAME="$${VAR_BASE_NAME}_SENTINEL"; \
	DIR_VAR_NAME="$${VAR_BASE_NAME}_DIR"; \
	\
	# Dynamically get the VALUE of the make variables by recursively calling make.
	SENTINEL_FILE=$$( $(MAKE) -s --no-print-directory -f $(lastword $(MAKEFILE_LIST)) print-var VARNAME=$$SENTINEL_VAR_NAME ); \
	COMPILER_DIR=$$( $(MAKE) -s --no-print-directory -f $(lastword $(MAKEFILE_LIST)) print-var VARNAME=$$DIR_VAR_NAME ); \
	\
	# Ensure the compiler is built before benchmarking.
	if [ ! -f "$$SENTINEL_FILE" ]; then \
		$(call log,Compiler '$(COMPILER)' is not built yet. Building it first.); \
		$(MAKE) $(COMPILER); \
	fi; \
	\
	$(call log,Starting benchmark for '$(COMPILER)'); \
	\
	BENCHMARK_RUNS=$${BENCHMARK_RUNS:-10}; \
	TEMP_BUILD_DIR="$(DEV_DIR)/temp_benchmark_build_$(COMPILER)"; \
	METRICS_CSV="$(METRICS_DIR)/$(COMPILER)_metrics.csv"; \
	\
	echo "  -> Compiler Name: $(COMPILER)"; \
	echo "  -> Compiler Path: $$COMPILER_DIR"; \
	\
	mkdir -p "$(METRICS_DIR)"; \
	echo "Compiler,Run,RealTime_s,UserTime_s,SysTime_s" > "$$METRICS_CSV"; \
	\
	$(call log,Configuring LLD benchmark project for $(COMPILER)...); \
	rm -rf "$$TEMP_BUILD_DIR"; \
	cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$$TEMP_BUILD_DIR" \
		-D CMAKE_C_COMPILER="$${COMPILER_DIR}/bin/clang" \
		-D CMAKE_CXX_COMPILER="$${COMPILER_DIR}/bin/clang++" \
		-D CMAKE_BUILD_TYPE=Release \
		-D LLVM_ENABLE_PROJECTS=lld \
		-D LLVM_TARGETS_TO_BUILD=X86 \
		-D LLVM_ENABLE_RUNTIMES="" 1> /dev/null; \
	\
	for i in $$(seq 1 $$BENCHMARK_RUNS); do \
		$(call log,Benchmark Iteration $$i of $$BENCHMARK_RUNS for $(COMPILER)); \
		ninja -C "$$TEMP_BUILD_DIR" -t clean lld > /dev/null; \
		timing_output=$$((time -p ninja -j "$(JOBS)" -C "$$TEMP_BUILD_DIR" lld) 2>&1); \
		real_time=$$(echo "$$timing_output" | grep '^real' | awk '{print $$2}'); \
		user_time=$$(echo "$$timing_output" | grep '^user' | awk '{print $$2}'); \
		sys_time=$$(echo "$$timing_output" | grep '^sys' | awk '{print $$2}'); \
		echo "  Run $$i: Real=$$real_time s, User=$$user_time s, Sys=$$sys_time s"; \
		echo "$(COMPILER),$$i,$$real_time,$$user_time,$$sys_time" >> "$$METRICS_CSV"; \
	done; \
	\
	$(call log,Calculating statistics for $(COMPILER)); \
	awk -F, -v compiler="$(COMPILER)" ' \
		$$1 == compiler && $$2 ~ /^[0-9]+$$/ { \
			count++; real_sum += $$3; real_sum_sq += $$3*$$3; \
			user_sum += $$4; user_sum_sq += $$4*$$4; \
			sys_sum += $$5; sys_sum_sq += $$5*$$5; \
		} \
		END { \
			if (count > 0) { \
				real_avg = real_sum/count; user_avg = user_sum/count; sys_avg = sys_sum/count; \
				real_stddev = (count > 1) ? sqrt(real_sum_sq/count - real_avg*real_avg) : 0; \
				user_stddev = (count > 1) ? sqrt(user_sum_sq/count - user_avg*user_avg) : 0; \
				sys_stddev = (count > 1) ? sqrt(sys_sum_sq/count - sys_avg*sys_avg) : 0; \
				printf "%s,avg,%.3f,%.3f,%.3f\n", compiler, real_avg, user_avg, sys_avg; \
				printf "%s,stddev,%.3f,%.3f,%.3f\n", compiler, real_stddev, user_stddev, sys_stddev; \
			} \
		}' "$$METRICS_CSV" >> "$$METRICS_CSV"; \
	\
	rm -rf "$$TEMP_BUILD_DIR"; \
	$(call log,✅ Benchmark for '$(COMPILER)' complete. Results are in $$METRICS_CSV)

data:
	$(call log,Running Baseline Benchmark Suite)
	$(MAKE) benchmark COMPILER=bootstrapped_clang
	$(MAKE) benchmark COMPILER=fdo_clang

ipra_data:
	$(call log,Running IPRA Benchmark Suite)
	$(MAKE) benchmark COMPILER=ipra_fdo_clang
	$(MAKE) benchmark COMPILER=ipra_thinly_linked_fdo_clang
	$(MAKE) benchmark COMPILER=ipra_fully_linked_fdo_clang

linked_data:
	$(call log,Running LTO Benchmark Suite)
	$(MAKE) benchmark COMPILER=thinly_linked_fdo_clang
	$(MAKE) benchmark COMPILER=fully_linked_fdo_clang

# Target to clean up all build artifacts and metrics
clean:
	@$(call log,Cleaning up all build directories and metrics)
	@rm -rf "$(BOOTSTRAPPED_DIR)" "$(INSTR_DIR)" "$(FDO_DIR)" "$(THINLY_LINKED_DIR)"
	@echo "Cleanup complete."