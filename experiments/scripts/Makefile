# --- Configuration ---
SHELL := /bin/bash
.ONESHELL:
.PHONY: all bootstrapped_clang instr_clang instr_clang_data fdo_clang data clean

# Base directory for LLVM source code
LLVM_SRC_DIR := $(shell cd ../../ ; pwd)

# Development directory where all builds are stored
DEV_DIR := $(shell cd ../../../ ; pwd)

# Build directories
BOOTSTRAP_DIR := $(DEV_DIR)/bootstrapped_clang
INSTR_DIR := $(DEV_DIR)/instr_clang
FDO_DIR := $(DEV_DIR)/fdo_clang
THINLTO_DIR := $(DEV_DIR)/thinly_linked_fdo_clang
FULLLTO_DIR := $(DEV_DIR)/fully_linked_fdo_clang
METRICS_DIR := $(DEV_DIR)/metrics
IPRA_FDO_DIR := $(DEV_DIR)/ipra_fdo_clang
IPRA_THINLTO_DIR := $(DEV_DIR)/ipra_thinly_linked_fdo_clang
IPRA_FULLLTO_DIR := $(DEV_DIR)/ipra_fully_linked_fdo_clang

# Profile data directories and files
PROFILE_RAW_DIR := $(INSTR_DIR)/profiles
PROFILE_MERGED_FILE := $(INSTR_DIR)/clang.profdata

# Metrics file
METRICS_CSV := $(METRICS_DIR)/performance_metrics.csv
IPRA_METRICS_CSV := $(METRICS_DIR)/ipra_performance_metrics.csv
LINKED_METRICS_CSV := $(METRICS_DIR)/linked_performance_metrics.csv
LIVENESS_OUTPUT_DIR := $(METRICS_DIR)/liveness_output

# Number of parallel jobs to use for compilation
JOBS := $(shell nproc)

# Sentinel files to mark completion of a stage
BOOTSTRAP_SENTINEL := $(BOOTSTRAP_DIR)/.completed
INSTR_SENTINEL := $(INSTR_DIR)/.completed
FDO_SENTINEL := $(FDO_DIR)/.completed
THINLTO_SENTINEL := $(THINLTO_DIR)/.completed
FULLLTO_SENTINEL := $(FULLLTO_DIR)/.completed
IPRA_FDO_SENTINEL := $(IPRA_FDO_DIR)/.completed
IPRA_THINLTO_SENTINEL := $(IPRA_THINLTO_DIR)/.completed
IPRA_FULLLTO_SENTINEL := $(IPRA_FULLLTO_DIR)/.completed

# --- Helper Function (similar to log) ---
define log
	echo
	echo "--- $$(date '+%Y-%m-%d %H:%M:%S') ---"
	echo "--- $(1)"
	echo "-----------------------------------------------------"
endef

# --- Main Targets ---

# Default target: build everything up to the FDO-optimized clang
all: fdo_clang thinly_linked_fdo_clang ipra_fdo_clang ipra_thinly_linked_fdo_clang data ipra_data
experiments: ipra_fdo_clang ipra_thinly_linked_fdo_clang ipra_data
linked: thinly_linked_fdo_clang ipra_thinly_linked_fdo_clang fully_linked_fdo_clang ipra_fully_linked_fdo_clang

# Target 1: Build the initial, optimized 'bootstrapped_clang'
bootstrapped_clang: $(BOOTSTRAP_SENTINEL)
$(BOOTSTRAP_SENTINEL):
	$(call log,STEP 1: Building bootstrapped_clang (Release build with runtimes))
	cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(BOOTSTRAP_DIR)" \
	  -D CMAKE_BUILD_TYPE=Release \
	  -D LLVM_ENABLE_PROJECTS="clang;lld" \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_ENABLE_RUNTIMES="compiler-rt"
	ninja -j "$(JOBS)" -C "$(BOOTSTRAP_DIR)"
	@touch $@
	$(call log,✅ STEP 1: bootstrapped_clang built successfully.)

# Target 2: Build the instrumented 'instr_clang'
instr_clang: $(INSTR_SENTINEL)
$(INSTR_SENTINEL): $(BOOTSTRAP_SENTINEL)
	$(call log,STEP 2: Building instr_clang (Instrumented build))
	cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(INSTR_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAP_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAP_DIR)/bin/clang++" \
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
$(FDO_SENTINEL): $(BOOTSTRAP_SENTINEL) $(PROFILE_MERGED_FILE)
	@$(call log,STEP 5: Building fdo_clang (PGO-optimized build))
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(FDO_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAP_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAP_DIR)/bin/clang++" \
	  -D CMAKE_BUILD_TYPE=Release \
	  -D LLVM_ENABLE_PROJECTS=clang \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_PROFDATA_FILE="$(PROFILE_MERGED_FILE)"
	@ninja -j "$(JOBS)" -C "$(FDO_DIR)"
	@touch $@
	@$(call log,✅ STEP 5: fdo_clang built successfully.)

# NEW Target: Build the 'thinly_linked_fdo_clang' with PGO and ThinLTO
thinly_linked_fdo_clang: $(THINLTO_SENTINEL)
$(THINLTO_SENTINEL): $(BOOTSTRAP_SENTINEL) $(PROFILE_MERGED_FILE)
	@$(call log,STEP 5B: Building thinly_linked_fdo_clang (PGO + ThinLTO build))
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(THINLTO_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAP_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAP_DIR)/bin/clang++" \
	  -D CMAKE_BUILD_TYPE=Release \
	  -D LLVM_ENABLE_PROJECTS=clang \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_PROFDATA_FILE="$(PROFILE_MERGED_FILE)" \
	  -D LLVM_ENABLE_LTO=Thin \
	  -D LLVM_USE_LINKER=lld
	@ninja -j "$(JOBS)" -C "$(THINLTO_DIR)" && \
	touch $@ && \
	$(call log,✅ STEP 5B: thinly_linked_fdo_clang built successfully.)

# NEW Target: Build the 'thinly_linked_fdo_clang' with PGO and ThinLTO
fully_linked_fdo_clang: $(FULLLTO_SENTINEL)
$(FULLLTO_SENTINEL): $(BOOTSTRAP_SENTINEL) $(PROFILE_MERGED_FILE)
	@$(call log,STEP 5E: Building fully_linked_fdo_clang (PGO + FULLLTO build))
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(FULLLTO_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAP_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAP_DIR)/bin/clang++" \
	  -D CMAKE_BUILD_TYPE=Release \
	  -D LLVM_ENABLE_PROJECTS=clang \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_PROFDATA_FILE="$(PROFILE_MERGED_FILE)" \
	  -D LLVM_ENABLE_LTO=Full \
	  -D LLVM_USE_LINKER=lld
	@ninja -j "$(JOBS)" -C "$(FULLLTO_DIR)" && \
	touch $@ && \
	$(call log,✅ STEP 5E: fully_linked_fdo_clang built successfully.)

# NEW Target: Build the 'thinly_linked_fdo_clang' with PGO and ThinLTO
ipra_fully_linked_fdo_clang: $(IPRA_FULLLTO_SENTINEL)
$(IPRA_FULLLTO_SENTINEL): $(BOOTSTRAP_SENTINEL) $(PROFILE_MERGED_FILE)
	@$(call log,STEP 5F: Building ipra_fully_linked_fdo_clang (PGO + FULLLTO build))
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(FULLLTO_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAP_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAP_DIR)/bin/clang++" \
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
	@ninja -j "$(JOBS)" -C "$(IPRA_FULLLTO_DIR)" && \
	touch $@ && \
	$(call log,✅ STEP 5F: ipra_fully_linked_fdo_clang built successfully.)

# NEW Target: Build 'ipra_fdo_clang' with PGO and the IPRA optimization.
ipra_fdo_clang: $(IPRA_FDO_SENTINEL)
$(IPRA_FDO_SENTINEL): $(BOOTSTRAP_SENTINEL) $(PROFILE_MERGED_FILE)
	@$(call log,STEP 5C: Building ipra_fdo_clang (PGO + IPRA build))
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(IPRA_FDO_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAP_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAP_DIR)/bin/clang++" \
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
ipra_thinly_linked_fdo_clang: $(IPRA_THINLTO_SENTINEL)
$(IPRA_THINLTO_SENTINEL): $(BOOTSTRAP_SENTINEL) $(PROFILE_MERGED_FILE)
	@$(call log,STEP 5D: Building ipra_thinly_linked_fdo_clang (PGO + ThinLTO + IPRA build))
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(IPRA_THINLTO_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAP_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAP_DIR)/bin/clang++" \
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
	@ninja -j "$(JOBS)" -C "$(IPRA_THINLTO_DIR)" && \
	touch $@ && \
	$(call log,✅ STEP 5D: ipra_thinly_linked_fdo_clang built successfully.)

liveness_analysis: fdo_clang
	@$(call log,Collecting Liveness Data using fdo_clang)
	@mkdir -p "$(LIVENESS_OUTPUT_DIR)"
	@TEMP_LLD_BUILD_DIR="$(DEV_DIR)/temp_lld_for_liveness_analysis"
	@rm -rf "$$TEMP_LLD_BUILD_DIR"
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$$TEMP_LLD_BUILD_DIR" \
		-D CMAKE_C_COMPILER="$(BOOTSTRAP_DIR)/bin/clang" \
		-D CMAKE_CXX_COMPILER="$(BOOTSTRAP_DIR)/bin/clang++" \
		-D CMAKE_BUILD_TYPE=Release \
		-D LLVM_ENABLE_PROJECTS=lld \
		-D LLVM_TARGETS_TO_BUILD=X86 \
		-D LLVM_PROFDATA_FILE="$(PROFILE_MERGED_FILE)" \
		-D CMAKE_CXX_FLAGS="-mllvm -enable-cs-reg-liveness-analysis -mllvm -cs-reg-liveness-analysis-output-dir=$(LIVENESS_OUTPUT_DIR)"
	@ninja -j "$(JOBS)" -C "$$TEMP_LLD_BUILD_DIR" lld
	@rm -rf "$$TEMP_LLD_BUILD_DIR"
	@$(call log,✅ Liveness Data collected in $(LIVENESS_OUTPUT_DIR))

# Target 5: Benchmark compilers by rebuilding the LLD linker
data: $(FDO_SENTINEL)
	@$(call log,STEP 6: Benchmarking compiler performance by rebuilding LLD)
	@set -e; \
	BENCHMARK_RUNS=10; \
	mkdir -p "$(METRICS_DIR)"; \
	echo "Compiler,Run,RealTime_s,UserTime_s,SysTime_s" > "$(METRICS_CSV)"; \
	\
	# --- Pre-Benchmark Setup: Configure LLD build environments once ---
	TEMP_BUILD_DIR_BOOTSTRAP="$(DEV_DIR)/temp_benchmark_build_bootstrapped_clang"; \
	TEMP_BUILD_DIR_FDO="$(DEV_DIR)/temp_benchmark_build_fdo_clang"; \
	TEMP_BUILD_DIR_THINLTO="$(DEV_DIR)/temp_benchmark_build_thinly_linked_fdo_clang"; \
	\
	$(call log,Configuring LLD benchmark for bootstrapped_clang...); \
	rm -rf "$$TEMP_BUILD_DIR_BOOTSTRAP"; \
	cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$$TEMP_BUILD_DIR_BOOTSTRAP" \
		-D CMAKE_C_COMPILER="$(BOOTSTRAP_DIR)/bin/clang" \
		-D CMAKE_CXX_COMPILER="$(BOOTSTRAP_DIR)/bin/clang++" \
		-D CMAKE_BUILD_TYPE=Release \
		-D LLVM_ENABLE_PROJECTS=lld \
		-D LLVM_TARGETS_TO_BUILD=X86 \
		-D LLVM_ENABLE_RUNTIMES="" 1> /dev/null; \
	\
	$(call log,Configuring LLD benchmark for fdo_clang...); \
	rm -rf "$$TEMP_BUILD_DIR_FDO"; \
	cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$$TEMP_BUILD_DIR_FDO" \
		-D CMAKE_C_COMPILER="$(FDO_DIR)/bin/clang" \
		-D CMAKE_CXX_COMPILER="$(FDO_DIR)/bin/clang++" \
		-D CMAKE_BUILD_TYPE=Release \
		-D LLVM_ENABLE_PROJECTS=lld \
		-D LLVM_TARGETS_TO_BUILD=X86 \
		-D LLVM_ENABLE_RUNTIMES="" 1> /dev/null; \
	\
	$(call log,Configuring LLD benchmark for thinly_linked_fdo_clang...); \
	rm -rf "$$TEMP_BUILD_DIR_THINLTO"; \
	cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$$TEMP_BUILD_DIR_THINLTO" \
		-D CMAKE_C_COMPILER="$(THINLTO_DIR)/bin/clang" \
		-D CMAKE_CXX_COMPILER="$(THINLTO_DIR)/bin/clang++" \
		-D CMAKE_BUILD_TYPE=Release \
		-D LLVM_ENABLE_PROJECTS=lld \
		-D LLVM_TARGETS_TO_BUILD=X86 \
		-D LLVM_ENABLE_RUNTIMES="" 1> /dev/null; \
	\
	# This function now times a clean rebuild of the 'lld' target in a pre-configured directory.
	run_benchmark() { \
		local compiler_name=$$1; \
		local temp_build_dir=$$2; \
		local run_num=$$3; \
		\
		# CRITICAL: Clean the 'lld' target specifically to force a rebuild for timing.
		ninja -C "$$temp_build_dir" -t clean lld 1> /dev/null; \
		\
		# Time the ninja rebuild process for just the 'lld' target.
		timing_output=$$( \
			(time -p ninja -j $(JOBS) -C "$$temp_build_dir" lld) 2>&1 \
		); \
		\
		real_time=$$(echo "$$timing_output" | grep '^real' | awk '{print $$2}'); \
		user_time=$$(echo "$$timing_output" | grep '^user' | awk '{print $$2}'); \
		sys_time=$$(echo "$$timing_output" | grep '^sys' | awk '{print $$2}'); \
		echo "  Run $$run_num: Real=$$real_time\s, User=$$user_time\s, Sys=$$sys_time\s"; \
		echo "$$compiler_name,$$run_num,$$real_time,$$user_time,$$sys_time" >> "$(METRICS_CSV)"; \
	}; \
	\
	# This function calculates and appends summary statistics to the CSV.
	calculate_stats() { \
		local compiler_name=$$1; \
		$(call log,Calculating statistics for $$compiler_name); \
		awk -F, -v compiler="$$compiler_name" ' \
			$$1 == compiler && $$2 ~ /^[0-9]+$$/ { \
				count++; \
				real_sum += $$3; real_sum_sq += $$3*$$3; \
				user_sum += $$4; user_sum_sq += $$4*$$4; \
				sys_sum += $$5; sys_sum_sq += $$5*$$5; \
			} \
			END { \
				if (count > 0) { \
					real_avg = real_sum/count; \
					user_avg = user_sum/count; \
					sys_avg = sys_sum/count; \
					\
					real_stddev = (count > 1) ? sqrt(real_sum_sq/count - real_avg*real_avg) : 0; \
					user_stddev = (count > 1) ? sqrt(user_sum_sq/count - user_avg*user_avg) : 0; \
					sys_stddev = (count > 1) ? sqrt(sys_sum_sq/count - sys_avg*sys_avg) : 0; \
					\
					printf "%s,avg,%.3f,%.3f,%.3f\n", compiler, real_avg, user_avg, sys_avg; \
					printf "%s,stddev,%.3f,%.3f,%.3f\n", compiler, real_stddev, user_stddev, sys_stddev; \
				} \
			}' "$(METRICS_CSV)" >> "$(METRICS_CSV)"; \
	}; \
	\
	# --- Main Execution Loop ---
	for i in $$(seq 1 $$BENCHMARK_RUNS); do \
		$(call log,Benchmark Iteration $$i of $$BENCHMARK_RUNS); \
		run_benchmark "bootstrapped_clang" "$$TEMP_BUILD_DIR_BOOTSTRAP" $$i; \
		run_benchmark "fdo_clang" "$$TEMP_BUILD_DIR_FDO" $$i; \
		run_benchmark "thinly_linked_fdo_clang" "$$TEMP_BUILD_DIR_THINLTO" $$i; \
	done; \
	\
	# --- Post-Benchmark Cleanup & Analysis ---
	rm -rf "$$TEMP_BUILD_DIR_BOOTSTRAP" "$$TEMP_BUILD_DIR_FDO" "$$TEMP_BUILD_DIR_THINLTO"; \
	calculate_stats "bootstrapped_clang"; \
	calculate_stats "fdo_clang"; \
	calculate_stats "thinly_linked_fdo_clang"; \
	\
	$(call log,✅ All tasks complete. Benchmark results are in $(METRICS_CSV))

# NEW Target: Benchmark the IPRA optimization using the existing compilers.
ipra_data: fdo_clang thinly_linked_fdo_clang
	@$(call log,STEP 7: Benchmarking IPRA compiler performance by rebuilding LLD)
	@set -e; \
	BENCHMARK_RUNS=10; \
	mkdir -p "$(METRICS_DIR)"; \
	echo "Compiler,Run,RealTime_s,UserTime_s,SysTime_s" > "$(IPRA_METRICS_CSV)"; \
	\
	# --- Pre-Benchmark Setup: Configure LLD build environments once ---
	TEMP_BUILD_DIR_IPRA_FDO="$(DEV_DIR)/temp_benchmark_build_fdo_clang"; \
	TEMP_BUILD_DIR_IPRA_THINLTO="$(DEV_DIR)/temp_benchmark_build_thinly_linked_fdo_clang"; \
	\
	$(call log,Configuring LLD benchmark for fdo_clang with IPRA...); \
	rm -rf "$$TEMP_BUILD_DIR_IPRA_FDO"; \
	cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$$TEMP_BUILD_DIR_IPRA_FDO" \
		-D CMAKE_C_COMPILER="$(IPRA_FDO_DIR)/bin/clang" \
		-D CMAKE_CXX_COMPILER="$(IPRA_FDO_DIR)/bin/clang++" \
		-D CMAKE_BUILD_TYPE=Release \
		-D LLVM_ENABLE_PROJECTS=lld \
		-D LLVM_TARGETS_TO_BUILD=X86 \
		-D LLVM_ENABLE_RUNTIMES="" 1> /dev/null; \
	\
	$(call log,Configuring LLD benchmark for thinly_linked_fdo_clang with IPRA...); \
	rm -rf "$$TEMP_BUILD_DIR_IPRA_THINLTO"; \
	cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$$TEMP_BUILD_DIR_IPRA_THINLTO" \
		-D CMAKE_C_COMPILER="$(IPRA_THINLTO_DIR)/bin/clang" \
		-D CMAKE_CXX_COMPILER="$(IPRA_THINLTO_DIR)/bin/clang++" \
		-D CMAKE_BUILD_TYPE=Release \
		-D LLVM_ENABLE_PROJECTS=lld \
		-D LLVM_TARGETS_TO_BUILD=X86 \
		-D LLVM_ENABLE_RUNTIMES="" 1> /dev/null; \
	\
	# This function now times a clean rebuild of the 'lld' target in a pre-configured directory.
	run_benchmark() { \
		local compiler_name=$$1; local temp_build_dir=$$2; local run_num=$$3; \
		ninja -C "$$temp_build_dir" -t clean lld 1> /dev/null; \
		timing_output=$$( (time -p ninja -j $(JOBS) -C "$$temp_build_dir" lld) 2>&1 ); \
		real_time=$$(echo "$$timing_output" | grep '^real' | awk '{print $$2}'); \
		user_time=$$(echo "$$timing_output" | grep '^user' | awk '{print $$2}'); \
		sys_time=$$(echo "$$timing_output" | grep '^sys' | awk '{print $$2}'); \
		echo "  Run $$run_num: Real=$$real_time\s, User=$$user_time\s, Sys=$$sys_time\s"; \
		echo "$$compiler_name,$$run_num,$$real_time,$$user_time,$$sys_time" >> "$(IPRA_METRICS_CSV)"; \
	}; \
	\
	# This function calculates and appends summary statistics to the CSV.
	calculate_stats() { \
		local compiler_name=$$1; \
		$(call log,Calculating statistics for $$compiler_name); \
		awk -F, -v compiler="$$compiler_name" ' \
			$$1 == compiler && $$2 ~ /^[0-9]+$$/ { count++; real_sum += $$3; real_sum_sq += $$3*$$3; user_sum += $$4; user_sum_sq += $$4*$$4; sys_sum += $$5; sys_sum_sq += $$5*$$5; } \
			END { \
				if (count > 0) { \
					real_avg = real_sum/count; \
					user_avg = user_sum/count; \
					sys_avg = sys_sum/count; \
					\
					real_stddev = (count > 1) ? sqrt(real_sum_sq/count - real_avg*real_avg) : 0; \
					user_stddev = (count > 1) ? sqrt(user_sum_sq/count - user_avg*user_avg) : 0; \
					sys_stddev = (count > 1) ? sqrt(sys_sum_sq/count - sys_avg*sys_avg) : 0; \
					\
					printf "%s,avg,%.3f,%.3f,%.3f\n", compiler, real_avg, user_avg, sys_avg; \
					printf "%s,stddev,%.3f,%.3f,%.3f\n", compiler, real_stddev, user_stddev, sys_stddev; \
				} \
			}' "$(IPRA_METRICS_CSV)" >> "$(IPRA_METRICS_CSV)"; \
	}; \
	\
	# --- Main Execution Loop ---
	for i in $$(seq 1 $$BENCHMARK_RUNS); do \
		$(call log,Benchmark Iteration $$i of $$BENCHMARK_RUNS); \
		run_benchmark "ipra_fdo_clang" "$$TEMP_BUILD_DIR_IPRA_FDO" $$i; \
		run_benchmark "ipra_thinly_linked_fdo_clang" "$$TEMP_BUILD_DIR_IPRA_THINLTO" $$i; \
	done; \
	\
	# --- Post-Benchmark Cleanup & Analysis ---
	rm -rf "$$TEMP_BUILD_DIR_IPRA_FDO" "$$TEMP_BUILD_DIR_IPRA_THINLTO"; \
	# FIX: Calculate stats for the correct IPRA compilers.
	calculate_stats "ipra_fdo_clang"; \
	calculate_stats "ipra_thinly_linked_fdo_clang"; \
	\
	$(call log,✅ All tasks complete. IPRA benchmark results are in $(IPRA_METRICS_CSV))


# Target to clean up all build artifacts and metrics
clean:
	@$(call log,Cleaning up all build directories and metrics)
	@rm -rf "$(BOOTSTRAP_DIR)" "$(INSTR_DIR)" "$(FDO_DIR)" "$(THINLTO_DIR)"
	@echo "Cleanup complete."
