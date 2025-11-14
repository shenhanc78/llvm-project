#
# Makefile for MySQL ThinLTO+AutoFDO vs. PreserveNone+ThinLTO+AutoFDO Benchmarking
# (Version 8.4.7 - Using System OpenSSL)
#

SHELL := /bin/bash
.ONESHELL:
.PHONY: all setup_source autofdo_collect_perf autofdo_convert_profile benchmark

# --- Configuration ---

# Get the current directory (mysql_benchmarks)
CUR_DIR := $(shell pwd)

# Base directory for all builds, profiles, and source code
# Relative to this Makefile (llvm-project/experiments/scripts/mysql_benchmarks)
DEV_DIR := $(shell mkdir -p ../../../../ipra-run ; cd ../../../../ipra-run ; pwd)
METRICS_DIR := $(shell mkdir -p ../../metrics ; cd ../../metrics ; pwd)

# Specific directory for this benchmark's data
BENCHMARK_BASE_DIR := $(DEV_DIR)/mysql_benchmark
SOURCE_BASE_DIR := $(BENCHMARK_BASE_DIR)/source

# Source directories
MYSQL_SOURCE_DIR := $(SOURCE_BASE_DIR)/mysql-8.4.7
OPENSSL_SOURCE_DIR := $(SOURCE_BASE_DIR)/openssl-3.0.5
NCURSE_SOURCE_DIR := $(SOURCE_BASE_DIR)/ncurses-6.3

# We assume the 'bootstrapped_clang' build from your other Makefile exists
# and we will use it as the compiler.
BOOTSTRAPPED_DIR := $(DEV_DIR)/bootstrapped_clang
NCC := $(BOOTSTRAPPED_DIR)/bin/clang
NCXX := $(BOOTSTRAPPED_DIR)/bin/clang++

# Number of parallel jobs
JOBS := $(shell nproc)

# --- Compiler Build Definitions ---

# Master list of all MySQL build names
# --- NEW: Added baseline_mysql and thinlto_mysql ---
COMPILER_LIST := \
	baseline_mysql \
	thinlto_mysql \
	autofdo_metadata_mysql \
	thinlto_autofdo_mysql \
	pn_thinlto_autofdo_mysql

# Loop through the list and automatically define the build directory variables
$(foreach compiler, $(COMPILER_LIST), \
	$(eval COMPILER_BASE_LOWER := $(patsubst %_mysql,%,$(compiler))) \
	$(eval COMPILER_BASE_UPPER := $(shell echo $(COMPILER_BASE_LOWER) | tr '[:lower:]' '[:upper:]')) \
	$(eval $(COMPILER_BASE_UPPER)_MYSQL_DIR := $(BENCHMARK_BASE_DIR)/$(compiler)) \
	$(eval $(COMPILER_BASE_UPPER)_MYSQL_LIVENESS_OUTPUT_DIR := $(METRICS_DIR)/liveness_output/$(COMPILER_BASE_LOWER)_mysql_liveness_output) \
	$(eval $(COMPILER_BASE_UPPER)_MYSQL_PN_FUNCTIONS_DIR := $(METRICS_DIR)/pn_functions/$(COMPILER_BASE_LOWER)_mysql_pn_functions) \
)

# Profile data files
AUTOFDO_PERF_FILE := $(AUTOFDO_METADATA_MYSQL_DIR)/perf.data
AUTOFDO_PROFILE_FILE := $(AUTOFDO_METADATA_MYSQL_DIR)/clang.prof

# --- Helper Function (Log) ---
define log
	echo
	echo "--- $$(date '+%Y-%m-%d %H:%M:%S') ---"
	echo "--- $(1)"
	echo "-----------------------------------------------------"
endef

# --- Main Targets ---

# --- NEW: Added baseline_mysql and thinlto_mysql to the default 'all' target ---
all: baseline_mysql thinlto_mysql thinlto_autofdo_mysql pn_thinlto_autofdo_mysql

# Target 0: Download, patch, and build dependencies
setup_source: $(SOURCE_BASE_DIR)/.setup_complete

$(SOURCE_BASE_DIR)/.setup_complete:
	$(call log,Setting up MySQL source and dependencies)
	./setup.sh
	$(call log,✅ Source setup complete.)

# --- Common CMake Flags for MySQL ---
# These are adapted from your mysqlbuild.mk
define COMMON_CMAKE_FLAGS
	-G Ninja \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_C_COMPILER="$(NCC)" \
	-DCMAKE_CXX_COMPILER="$(NCXX)" \
	-DCMAKE_LINKER="$(BOOTSTRAPPED_DIR)/bin/ld.lld" \
	-DWITH_BOOST=$(MYSQL_SOURCE_DIR)/boost \
	-DWITH_SSL=system \
	-DCMAKE_PREFIX_PATH="$(NCURSE_SOURCE_DIR)/install" \
	-DWITH_LTO=OFF \
	-DBUILD_SHARED_LIBS=OFF \
	-DWITHOUT_GROUP_REPLICATION=ON \
	-Dprotobuf_BUILD_SHARED_LIBS=OFF \
	-DWITH_ROUTER=Off \
	-DWITH_UNIT_TESTS=Off \
	-DENABLED_PROFILING=Off \
	-DCMAKE_INSTALL_PREFIX=$(1)/install
endef

# --- NEW: Sanity Check: Baseline Build (No LTO, No FDO) ---
baseline_mysql:
	@$(call log, Building baseline_mysql (Release build, no LTO, no FDO))
	mkdir -p "$(BASELINE_MYSQL_DIR)"
	# COMMON_CMAKE_FLAGS already sets -DWITH_LTO=OFF.
	# We use similar flags for consistency, but without -flto=thin.
	CFLAGS="-gmlt -fdebug-info-for-profiling -mllvm -enable-fs-discriminator=true -mllvm -improved-fs-discriminator=true -ffunction-sections -fdata-sections";
	CXXFLAGS="-gmlt -fdebug-info-for-profiling -mllvm -enable-fs-discriminator=true -mllvm -improved-fs-discriminator=true -ffunction-sections -fdata-sections";
	LFLAGS="-fuse-ld=lld -Wl,--mllvm=-enable-fs-discriminator=true -Wl,--mllvm=-improved-fs-discriminator=true -static-libgcc -static-libstdc++";
	@cmake -S "$(MYSQL_SOURCE_DIR)" -B "$(BASELINE_MYSQL_DIR)" \
		$(call COMMON_CMAKE_FLAGS,$(BASELINE_MYSQL_DIR)) \
		-DCMAKE_C_FLAGS="$${CFLAGS}" \
		-DCMAKE_CXX_FLAGS="$${CXXFLAGS}" \
		-DCMAKE_EXE_LINKER_FLAGS="$${LFLAGS}" \
		-DCMAKE_SHARED_LINKER_FLAGS="$${LFLAGS}" \
		-DCMAKE_MODULE_LINKER_FLAGS="$${LFLAGS}";
	@ninja -j "$(JOBS)" -C "$(BASELINE_MYSQL_DIR)" install;
	@touch $@;
	@$(call log,✅ baseline_mysql built successfully.)

# --- NEW: Sanity Check: ThinLTO Build (No FDO) ---
thinlto_mysql:
	@$(call log, Building thinlto_mysql (ThinLTO optimized build, no FDO))
	mkdir -p "$(THINLTO_MYSQL_DIR)"
	# These flags are from thinlto_autofdo_mysql, but *without* profile-use flags
	CFLAGS="-gmlt -fdebug-info-for-profiling -mllvm -enable-fs-discriminator=true -mllvm -improved-fs-discriminator=true -ffunction-sections -fdata-sections -flto=thin";
	CXXFLAGS="-gmlt -fdebug-info-for-profiling -mllvm -enable-fs-discriminator=true -mllvm -improved-fs-discriminator=true -ffunction-sections -fdata-sections -flto=thin";
	LFLAGS="-fuse-ld=lld -Wl,--mllvm=-enable-fs-discriminator=true -Wl,--mllvm=-improved-fs-discriminator=true -flto=thin -static-libgcc -static-libstdc++";
	@cmake -S "$(MYSQL_SOURCE_DIR)" -B "$(THINLTO_MYSQL_DIR)" \
		$(call COMMON_CMAKE_FLAGS,$(THINLTO_MYSQL_DIR)) \
		-DCMAKE_C_FLAGS="$${CFLAGS}" \
		-DCMAKE_CXX_FLAGS="$${CXXFLAGS}" \
		-DCMAKE_EXE_LINKER_FLAGS="$${LFLAGS}" \
		-DCMAKE_SHARED_LINKER_FLAGS="$${LFLAGS}" \
		-DCMAKE_MODULE_LINKER_FLAGS="$${LFLAGS}";
	@ninja -j "$(JOBS)" -C "$(THINLTO_MYSQL_DIR)" install;
	@touch $@;
	@$(call log,✅ thinlto_mysql built successfully.)

# --- AutoFDO Build Targets ---

# Target 1: Build MySQL with AutoFDO metadata flags
autofdo_metadata_mysql:
	$(call log,STEP AFDO-1: Building autofdo_metadata_mysql)
	mkdir -p "$(AUTOFDO_METADATA_MYSQL_DIR)"
	CFLAGS="-gmlt -fdebug-info-for-profiling -mllvm -enable-fs-discriminator=true -mllvm -improved-fs-discriminator=true -flto=thin";
	CXXFLAGS="-gmlt -fdebug-info-for-profiling -mllvm -enable-fs-discriminator=true -mllvm -improved-fs-discriminator=true -flto=thin";
	LFLAGS="-fuse-ld=lld -Wl,--mllvm=-enable-fs-discriminator=true -Wl,--mllvm=-improved-fs-discriminator=true -Wl,--build-id -flto=thin -static-libgcc -static-libstdc++";
	cmake -S "$(MYSQL_SOURCE_DIR)" -B "$(AUTOFDO_METADATA_MYSQL_DIR)" \
		$(call COMMON_CMAKE_FLAGS,$(AUTOFDO_METADATA_MYSQL_DIR)) \
		-DCMAKE_C_FLAGS="$${CFLAGS}" \
		-DCMAKE_CXX_FLAGS="$${CXXFLAGS}" \
		-DCMAKE_EXE_LINKER_FLAGS="$${LFLAGS}" \
		-DCMAKE_SHARED_LINKER_FLAGS="$${LFLAGS}" \
		-DCMAKE_MODULE_LINKER_FLAGS="$${LFLAGS}" && \
	ninja -j "$(JOBS)" -C "$(AUTOFDO_METADATA_MYSQL_DIR)" install && \
	@touch $@ && \
	$(call log,✅ autofdo_metadata_mysql built successfully.)

# Target 2: Collect perf profile data using the metadata build
autofdo_collect_perf:
	@$(call log, STEP AFDO-2: Collecting perf profile data)
	@set -e; \
	rm -f "$(AUTOFDO_PERF_FILE)"; \
	perf record -e BR_INST_RETIRED.NEAR_TAKEN:u -b -c 500009 \
		-o "$(AUTOFDO_PERF_FILE)" -- \
		./run-benchmark.sh "$(AUTOFDO_METADATA_MYSQL_DIR)" "loadtest";
	$(call log,✅ Perf data collected at $(AUTOFDO_PERF_FILE))

# Target 3: Convert perf data to LLVM profile format
autofdo_convert_profile:
	$(call log, STEP AFDO-3: Converting perf data to LLVM profile)
	# --- FIX: Using ./create_llvm_prof, as in your Clang Makefile ---
	../create_llvm_prof --binary="$(AUTOFDO_METADATA_MYSQL_DIR)/install/bin/mysqld" \
					 --profile="$(AUTOFDO_PERF_FILE)" \
					 --format=extbinary \
					 --out="$(AUTOFDO_PROFILE_FILE)" && \
	$(call log,✅ LLVM profile created at $(AUTOFDO_PROFILE_FILE))

# Target 4: Build the baseline ThinLTO + AutoFDO MySQL
thinlto_autofdo_mysql:
	@$(call log, Building thinlto_autofdo_mysql (ThinLTO + AutoFDO optimized build))
	mkdir -p "$(THINLTO_AUTOFDO_MYSQL_DIR)"
	CFLAGS="-gmlt -fdebug-info-for-profiling -mllvm -enable-fs-discriminator=true -mllvm -improved-fs-discriminator=true -fprofile-sample-use=$(AUTOFDO_PROFILE_FILE) -ffunction-sections -fdata-sections -flto=thin";
	CXXFLAGS="-gmlt -fdebug-info-for-profiling -mllvm -enable-fs-discriminator=true -mllvm -improved-fs-discriminator=true -fprofile-sample-use=$(AUTOFDO_PROFILE_FILE) -ffunction-sections -fdata-sections -flto=thin";
	LFLAGS="-fuse-ld=lld -Wl,--mllvm=-enable-fs-discriminator=true -Wl,--mllvm=-improved-fs-discriminator=true -Wl,--lto-sample-profile=$(AUTOFDO_PROFILE_FILE) -flto=thin -static-libgcc -static-libstdc++";
	@cmake -S "$(MYSQL_SOURCE_DIR)" -B "$(THINLTO_AUTOFDO_MYSQL_DIR)" \
		$(call COMMON_CMAKE_FLAGS,$(THINLTO_AUTOFDO_MYSQL_DIR)) \
		-DCMAKE_C_FLAGS="$${CFLAGS}" \
		-DCMAKE_CXX_FLAGS="$${CXXFLAGS}" \
		-DCMAKE_EXE_LINKER_FLAGS="$${LFLAGS}" \
		-DCMAKE_SHARED_LINKER_FLAGS="$${LFLAGS}" \
		-DCMAKE_MODULE_LINKER_FLAGS="$${LFLAGS}";
	@ninja -j "$(JOBS)" -C "$(THINLTO_AUTOFDO_MYSQL_DIR)" install;
	@touch $@;
	@$(call log,✅ thinlto_autofdo_mysql built successfully.)

# Target 5: Build the experimental PreserveNone + ThinLTO + AutoFDO MySQL
pn_thinlto_autofdo_mysql:
	@$(call log,Building pn_thinlto_autofdo_mysql)
	@set -e; \
	mkdir -p "$(PN_THINLTO_AUTOFDO_MYSQL_DIR)"; \
	PN_PROFILE="$(THINLTO_AUTOFDO_MYSQL_PN_FUNCTIONS_DIR)/liveness_profdata.json"; \
	echo "--- Using PreserveNone JSON Profile: $${PN_PROFILE}"; \
	CFLAGS="-gmlt -fdebug-info-for-profiling -mllvm -enable-fs-discriminator=true -mllvm -improved-fs-discriminator=true -fprofile-sample-use=$(AUTOFDO_PROFILE_FILE) -ffunction-sections -fdata-sections -flto=thin";
	CXXFLAGS="-gmlt -fdebug-info-for-profiling -mllvm -enable-fs-discriminator=true -mllvm -improved-fs-discriminator=true -fprofile-sample-use=$(AUTOFDO_PROFILE_FILE) -ffunction-sections -fdata-sections -flto=thin";
	LFLAGS="-fuse-ld=lld -Wl,--mllvm=-enable-fs-discriminator=true -Wl,--mllvm=-improved-fs-discriminator=true -Wl,--lto-sample-profile=$(AUTOFDO_PROFILE_FILE) -Wl,-mllvm,-preserve-none-enable -Wl,-mllvm,-preserve-none-json=$${PN_PROFILE} -flto=thin -static-libgcc -static-libstdc++";
	@cmake -S "$(MYSQL_SOURCE_DIR)" -B "$(PN_THINLTO_AUTOFDO_MYSQL_DIR)" \
		$(call COMMON_CMAKE_FLAGS,$(PN_THINLTO_AUTOFDO_MYSQL_DIR)) \
		-DCMAKE_C_FLAGS="$${CFLAGS}" \
		-DCMAKE_CXX_FLAGS="$${CXXFLAGS}" \
		-DCMAKE_EXE_LINKER_FLAGS="$${LFLAGS}" \
		-DCMAKE_SHARED_LINKER_FLAGS="$${LFLAGS}" \
		-DCMAKE_MODULE_LINKER_FLAGS="$${LFLAGS}";
	@ninja -j "$(JOBS)" -C "$(PN_THINLTO_AUTOFDO_MYSQL_DIR)" install;
	@touch $@;
	@$(call log,✅ pn_thinlto_autofdo_mysql built successfully.)

# --- Liveness Analysis Target ---

thinlto_autofdo_mysql_liveness_analysis:
	@$(call log,Collecting Liveness Data using thinlto_autofdo_mysql build flags)
	@mkdir -p "$(THINLTO_AUTOFDO_MYSQL_LIVENESS_OUTPUT_DIR)"
	@TEMP_MYSQL_BUILD_DIR="$(BENCHMARK_BASE_DIR)/temp_mysql_for_liveness_analysis"
	@rm -rf "$$TEMP_MYSQL_BUILD_DIR"
	CFLAGS="-gmlt -fdebug-info-for-profiling -mllvm -enable-fs-discriminator=true -mllvm -improved-fs-discriminator=true -fprofile-sample-use=$(AUTOFDO_PROFILE_FILE) -ffunction-sections -fdata-sections -flto=thin";
	CXXFLAGS="-gmlt -fdebug-info-for-profiling -mllvm -enable-fs-discriminator=true -mllvm -improved-fs-discriminator=true -fprofile-sample-use=$(AUTOFDO_PROFILE_FILE) -ffunction-sections -fdata-sections -flto=thin";
	LFLAGS="-fuse-ld=lld -Wl,--mllvm=-enable-fs-discriminator=true -Wl,--mllvm=-improved-fs-discriminator=true -Wl,--lto-sample-profile=$(AUTOFDO_PROFILE_FILE) -Wl,-mllvm,-enable-cs-reg-liveness-analysis -Wl,-mllvm,-cs-reg-liveness-analysis-output-dir=$(THINLTO_AUTOFDO_MYSQL_LIVENESS_OUTPUT_DIR) -Wl,-mllvm,-enable-ipra-prera-analysis -Wl,-mllvm,-ipra-dry-run -Wl,-mllvm,-ipra-prera-analysis-output-dir=$(THINLTO_AUTOFDO_MYSQL_LIVENESS_OUTPUT_DIR) -flto=thin -static-libgcc -static-libstdc++";
	@cmake -S "$(MYSQL_SOURCE_DIR)" -B "$$TEMP_MYSQL_BUILD_DIR" \
		$(call COMMON_CMAKE_FLAGS,$$TEMP_MYSQL_BUILD_DIR) \
		-DCMAKE_C_FLAGS="$${CFLAGS}" \
		-DCMAKE_CXX_FLAGS="$${CXXFLAGS}" \
		-DCMAKE_EXE_LINKER_FLAGS="$${LFLAGS}" \
		-DCMAKE_SHARED_LINKER_FLAGS="$${LFLAGS}" \
		-DCMAKE_MODULE_LINKER_FLAGS="$${LFLAGS}";
	@ninja -j "$(JOBS)" -C "$$TEMP_MYSQL_BUILD_DIR" install;
	@rm -rf "$$TEMP_MYSQL_BUILD_DIR";
	@$(call log,✅ Liveness Data collected in $(THINLTO_AUTOFDO_MYSQL_LIVENESS_DIR))

# --- Benchmarking Target ---

# Usage: make benchmark TARGET=<target_name> [BENCHMARK_RUNS=N]
benchmark:
	@if [ -z "$(TARGET)" ]; then \
		echo "Error: You must specify which target to benchmark."; \
		echo "Usage: make benchmark TARGET=<name>"; \
		echo "e.g., make benchmark TARGET=thinlto_autofdo_mysql"; \
		exit 1; \
	fi

	@set -e; \
	\
	# Dynamically construct the variable names based on the TARGET input.
	VAR_BASE_NAME=$$(echo $(TARGET) | tr '[:lower:]' '[:upper:]' | sed 's/_MYSQL$$//'); \
	DIR_VAR_NAME="$${VAR_BASE_NAME}_MYSQL_DIR"; \
	\
	# Dynamically get the VALUE of the make variables
	TARGET_DIR=$$( $(MAKE) -s --no-print-directory -f $(lastword $(MAKEFILE_LIST)) print-var VARNAME=$$DIR_VAR_NAME ); \
	\
	$(call log,Starting benchmark for '$(TARGET)'); \
	\
	BENCHMARK_RUNS=$${BENCHMARK_RUNS:-1}; \
	METRICS_CSV="$(METRICS_DIR)/benchmark_results/$(TARGET)_metrics.csv"; \
	\
	echo "  -> TARGET Name: $(TARGET)"; \
	echo "  -> TARGET Path: $$TARGET_DIR"; \
	echo "  -> Benchmark Runs: $$BENCHMARK_RUNS"; \
	echo "  -> Metrics File: $$METRICS_CSV"; \
	\
	mkdir -p "$(METRICS_DIR)/benchmark_results"; \
	\
	# Run the benchmark N times
	./run-benchmark.sh "$$TARGET_DIR" "benchmark" "$$BENCHMARK_RUNS"; \
	\
	# Parse the results
	$(call log,Parsing benchmark results for $(TARGET)); \
	./parse-results.sh "$$TARGET_DIR" "$$BENCHMARK_RUNS" > "$$METRICS_CSV"; \
	\
	cat "$$METRICS_CSV"; \
	$(call log,✅ Benchmark for '$(TARGET)' complete. Results are in $$METRICS_CSV)

print-var:
	@echo $($(VARNAME))

# --- NEW: Rebuild target, adapted from your Clang Makefile ---
# This runs the build and the part of the benchmark (setup) that fails
test_pn_thinlto_autofdo_mysql:
	@$(MAKE) rebuild TARGET=pn_thinlto_autofdo_mysql
	@./run-benchmark.sh "$(PN_THINLTO_AUTOFDO_MYSQL_DIR)" "benchmark" "1"

# Usage: make rebuild TARGET=<name>
rebuild:
	# Dynamically get the directory for the target
	VAR_BASE_NAME=$$(echo $(TARGET) | tr '[:lower:]' '[:upper:]' | sed 's/_MYSQL$$//'); \
	DIR_VAR_NAME="$${VAR_BASE_NAME}_MYSQL_DIR";
	TARGET_DIR=$$( $(MAKE) -s --no-print-directory -f $(lastword $(MAKEFILE_LIST)) print-var VARNAME=$$DIR_VAR_NAME ); \

	# Rebuild specified mysql build
	@$(call log,Rebuilding $(TARGET)...)
	@rm -rf $${TARGET_DIR}
	@rm -f $(TARGET)
	@$(MAKE) $(TARGET)

clean:
	@$(call log,Cleaning build and benchmark directories)
	rm -rf "$(BENCHMARK_BASE_DIR)"
	rm -f $(COMPILER_LIST)

clean-source:
	@$(call log,Cleaning all source files)
	rm -rf "$(SOURCE_BASE_DIR)"

size:
	@if [ -z "$(TARGET)" ]; then \
	echo "Error: You must specify which build to measure."; \
	echo "Usage: make size TARGET=<name>"; \
	exit 1; \
	fi

	@set -e; \
	\
	# Dynamically construct the variable names based on the TARGET input.
	VAR_BASE_NAME=$$(echo $(TARGET) | tr '[:lower:]' '[:upper:]' | sed 's/_MYSQL$$//'); \
	DIR_VAR_NAME="$${VAR_BASE_NAME}_MYSQL_DIR"; \
	\
	# Dynamically get the VALUE of the make variables by recursively calling make.
	TARGET_DIR=$$( $(MAKE) -s --no-print-directory -f $(lastword $(MAKEFILE_LIST)) print-var VARNAME=$$DIR_VAR_NAME ); \

	@size $${TARGET_DIR}/install/bin/mysqld;