# --- Configuration ---
SHELL := /bin/bash
.ONESHELL:
.PHONY:

# Base directory for LLVM source code
LLVM_SRC_DIR := $(shell cd ../../ ; pwd)

# Development directory where all builds are stored
DEV_DIR := $(shell mkdir -p ../../../ipra-run ; cd ../../../ipra-run ; pwd)
METRICS_DIR := $(shell cd ../metrics/ ; pwd)

# Master list of all compiler build names. To add a new compiler, just add it here.
COMPILER_LIST := \
	bootstrapped_clang \
	instr_clang \
	fdo_clang \
	thinlto_clang \
	thinlto_fdo_clang \
	fully_linked_fdo_clang \
	ipra_fdo_clang \
	ipra_thinlto_fdo_clang \
	ipra_fully_linked_fdo_clang \
	pn_fdo_clang \
	pn_thinlto_fdo_clang \
	pn_thinlto_autofdo_clang \
	pn_thinlto_autofdo_legacy_clang \
	autofdo_metadata_clang \
	thinlto_autofdo_clang \
	pn_ipra_thinlto_fdo_clang \
	pn_ipra_thinlto_autofdo_clang \


# Loop through the list and automatically define the dir and liveness_output variables.
$(foreach compiler, $(COMPILER_LIST), \
	$(eval COMPILER_BASE_LOWER := $(patsubst %_clang,%,$(compiler))) \
	$(eval COMPILER_BASE_UPPER := $(shell echo $(COMPILER_BASE_LOWER) | tr '[:lower:]' '[:upper:]')) \
	$(eval $(COMPILER_BASE_UPPER)_DIR := $(DEV_DIR)/$(compiler)) \
	$(eval $(COMPILER_BASE_UPPER)_LIVENESS_OUTPUT_DIR := $(METRICS_DIR)/liveness_output/$(COMPILER_BASE_LOWER)_liveness_output) \
	$(eval $(COMPILER_BASE_UPPER)_PN_FUNCTIONS_DIR := $(METRICS_DIR)/pn_functions/$(COMPILER_BASE_LOWER)_pn_functions) \
)

# Profile data directories and files
PROFILE_RAW_DIR := $(INSTR_DIR)/profiles
PROFILE_MERGED_FILE := $(INSTR_DIR)/clang.profdata
AUTOFDO_PERF_FILE := $(AUTOFDO_METADATA_DIR)/perf.data
AUTOFDO_PROFILE_FILE := $(AUTOFDO_METADATA_DIR)/clang.prof

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
# Target 1: Build the initial, optimized 'bootstrapped_clang'
bootstrapped_clang:
	$(call log,Building bootstrapped_clang (Release build with runtimes))
	cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(BOOTSTRAPPED_DIR)" \
	  -D CMAKE_BUILD_TYPE=Release \
	  -D LLVM_ENABLE_PROJECTS="clang;lld" \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_ENABLE_RUNTIMES="compiler-rt"
	ninja -j "$(JOBS)" -C "$(BOOTSTRAPPED_DIR)"
	@touch $@
	$(call log,✅ bootstrapped_clang built successfully.)

# Target 2: Build the instrumented 'instr_clang'
instr_clang:
	$(call log,Building instr_clang (Instrumented build))
	cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(INSTR_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
	  -D CMAKE_BUILD_TYPE=Release \
	  -D LLVM_ENABLE_PROJECTS="clang;lld" \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_BUILD_INSTRUMENTED=IR
	ninja -j "$(JOBS)" -C "$(INSTR_DIR)"
	@touch $@
	$(call log,✅ instr_clang built successfully.)

# Target 3: Generate and merge profile data
instr_clang_data:
	@$(call log,Generating profile data (.profraw files))
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
	ninja -j "$(JOBS)" -C "$$TEMP_PROFILE_BUILD_DIR"; \
	rm -rf "$$TEMP_PROFILE_BUILD_DIR"; \
	$(call log,✅ Profile data generated in $(PROFILE_RAW_DIR)); \
	$(call log,Merging profile data); \
	"$(INSTR_DIR)/bin/llvm-profdata" merge -j "$(JOBS)" -o "$@" "$(PROFILE_RAW_DIR)"/*.profraw; \
	$(call log,✅ Merged profile data created at $@)


# Target 4: Build the final 'fdo_clang' with Profile-Guided Optimizations
fdo_clang:
	@$(call log,Building fdo_clang (PGO-optimized build))
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(FDO_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
	  -D CMAKE_BUILD_TYPE=Release \
	  -D LLVM_ENABLE_PROJECTS=clang \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_PROFDATA_FILE="$(PROFILE_MERGED_FILE)"
	@ninja -j "$(JOBS)" -C "$(FDO_DIR)"
	@touch $@
	@$(call log,✅ fdo_clang built successfully.)

thinlto_clang:
	@$(call log,Building thinlto_clang)
	BUILD_TYPE=$${BUILD_TYPE:-Release};
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(THINLTO_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
	  -D CMAKE_BUILD_TYPE=$${BUILD_TYPE} \
	  -D LLVM_ENABLE_PROJECTS=clang \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_ENABLE_LTO=Thin \
	  -D LLVM_USE_LINKER=lld \
	  -D CMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld" \
	  -D CMAKE_SHARED_LINKER_FLAGS="-fuse-ld=lld" \
	  -D CMAKE_MODULE_LINKER_FLAGS="-fuse-ld=lld"
	@ninja -j "$(JOBS)" -C "$(THINLTO_DIR)" && \
	touch $@ && \
	$(call log,✅ thinlto_clang built successfully.)

# NEW Target: Build the 'thinlto_fdo_clang' with PGO and ThinLTO
thinlto_fdo_clang:
	@$(call log,Building thinlto_fdo_clang (PGO + ThinLTO build))
	BUILD_TYPE=$${BUILD_TYPE:-Release};
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(THINLTO_FDO_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
	  -D CMAKE_BUILD_TYPE=$${BUILD_TYPE}\
	  -D LLVM_ENABLE_PROJECTS=clang \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_PROFDATA_FILE="$(PROFILE_MERGED_FILE)" \
	  -D LLVM_ENABLE_LTO=Thin \
	  -D LLVM_USE_LINKER=lld \
	  -D CMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld" \
	  -D CMAKE_SHARED_LINKER_FLAGS="-fuse-ld=lld" \
	  -D CMAKE_MODULE_LINKER_FLAGS="-fuse-ld=lld"
	@ninja -j "$(JOBS)" -C "$(THINLTO_FDO_DIR)" && \
	touch $@ && \
	$(call log,✅ thinlto_fdo_clang built successfully.)

# NEW Target: Build the 'thinlto_fdo_clang' with PGO and ThinLTO
fully_linked_fdo_clang:
	@$(call log,Building fully_linked_fdo_clang (PGO + FULLLTO build))
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(FULLY_LINKED_FDO_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
	  -D CMAKE_BUILD_TYPE=Release \
	  -D LLVM_ENABLE_PROJECTS=clang \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_PROFDATA_FILE="$(PROFILE_MERGED_FILE)" \
	  -D LLVM_ENABLE_LTO=Full \
	  -D LLVM_USE_LINKER=lld \
	  -D CMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld" \
	  -D CMAKE_SHARED_LINKER_FLAGS="-fuse-ld=lld" \
	  -D CMAKE_MODULE_LINKER_FLAGS="-fuse-ld=lld"
	@ninja -j "$(JOBS)" -C "$(FULLY_LINKED_FDO_DIR)" && \
	touch $@ && \
	$(call log,✅ fully_linked_fdo_clang built successfully.)

# NEW Target: Build the 'thinlto_fdo_clang' with PGO and ThinLTO
ipra_fully_linked_fdo_clang:
	@$(call log,Building ipra_fully_linked_fdo_clang (PGO + FULLLTO build))
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
	$(call log,✅ ipra_fully_linked_fdo_clang built successfully.)

# NEW Target: Build 'ipra_fdo_clang' with PGO and the IPRA optimization.
ipra_fdo_clang:
	@$(call log,Building ipra_fdo_clang (PGO + IPRA build))
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
	$(call log,✅ ipra_fdo_clang built successfully.)

ipra_thinlto_fdo_clang:
	@$(call log, Building ipra_thinlto_fdo_clang (PGO + ThinLTO + IPRA build))
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(IPRA_THINLTO_FDO_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
	  -D CMAKE_BUILD_TYPE=Release \
	  -D LLVM_ENABLE_PROJECTS=clang \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_PROFDATA_FILE="$(PROFILE_MERGED_FILE)" \
	  -D LLVM_ENABLE_LTO=Thin \
	  -D LLVM_USE_LINKER=lld \
	  -D CMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld -Wl,-mllvm,-enable-ipra" \
	  -D CMAKE_SHARED_LINKER_FLAGS="-fuse-ld=lld -Wl,-mllvm,-enable-ipra" \
	  -D CMAKE_MODULE_LINKER_FLAGS="-fuse-ld=lld -Wl,-mllvm,-enable-ipra"
	@ninja -j "$(JOBS)" -C "$(IPRA_THINLTO_FDO_DIR)" && \
	touch $@ && \
	$(call log, ipra_thinlto_fdo_clang built successfully.)

# NEW Target: Build 'pn_ipra_thinlto_fdo_clang' with PGO, ThinLTO, and IPRA.
pn_ipra_thinlto_fdo_clang:
	@$(call log, Building ipra_thinlto_fdo_clang (PGO + ThinLTO + IPRA build))
	PN_PROFILE="$(IPRA_THINLTO_FDO_PN_FUNCTIONS_DIR)/liveness_profdata.json";
	LFLAGS="-fuse-ld=lld -Wl,-mllvm,-enable-ipra -Wl,-mllvm,-preserve-none-enable -Wl,-mllvm,-preserve-none-json=$${PN_PROFILE}";
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(PN_IPRA_THINLTO_FDO_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
	  -D CMAKE_BUILD_TYPE=Release \
	  -D LLVM_ENABLE_PROJECTS=clang \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_PROFDATA_FILE="$(PROFILE_MERGED_FILE)" \
	  -D LLVM_ENABLE_LTO=Thin \
	  -D LLVM_USE_LINKER=lld \
	  -D CMAKE_EXE_LINKER_FLAGS="$${LFLAGS}"
	  -D CMAKE_SHARED_LINKER_FLAGS="$${LFLAGS}" \
	  -D CMAKE_MODULE_LINKER_FLAGS="$${LFLAGS}"
	@ninja -j "$(JOBS)" -C "$(PN_IPRA_THINLTO_FDO_DIR)" && \
	touch $@ && \
	$(call log,✅ pn_ipra_thinlto_fdo_clang built successfully.)

# NEW Target: Build 'pn_fdo_clang' with PGO and the PreserveNonePass optimization.
pn_fdo_clang:
	@$(call log,Building pn_fdo_clang)
	@set -e; \
	# Define the path to the JSON profile locally for this target.
	PN_PROFILE="$(FDO_PN_FUNCTIONS_DIR)/liveness_profdata.json";
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(PN_FDO_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
	  -D CMAKE_BUILD_TYPE=Release \
	  -D LLVM_ENABLE_PROJECTS=clang \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_PROFDATA_FILE="$(PROFILE_MERGED_FILE)" \
	  -D CMAKE_C_FLAGS="-mllvm -preserve-none-enable -mllvm -preserve-none-json=$${PN_PROFILE}" \
	  -D CMAKE_CXX_FLAGS="-mllvm -preserve-none-enable -mllvm -preserve-none-json=$${PN_PROFILE}"
	@ninja -j "$(JOBS)" -C "$(PN_FDO_DIR)" && \
	touch $@ && \
	$(call log,✅ pn_fdo_clang built successfully.)

pn_thinlto_fdo_clang:
	@$(call log, Building pn_thinlto_fdo_clang)
	@set -e; \
	# Define the path to the JSON profile locally for this target.
	BUILD_TYPE=$${BUILD_TYPE:-Release};
	PN_PROFILE="$(THINLTO_FDO_PN_FUNCTIONS_DIR)/liveness_profdata.json";
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(PN_THINLTO_FDO_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
	  -D CMAKE_BUILD_TYPE=$${BUILD_TYPE} \
	  -D LLVM_ENABLE_PROJECTS=clang \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_ENABLE_LTO=Thin \
	  -D LLVM_USE_LINKER=lld \
	  -D LLVM_PROFDATA_FILE="$(PROFILE_MERGED_FILE)" \
	  -D CMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld -Wl,-mllvm,-preserve-none-enable -Wl,-mllvm,-preserve-none-json=$${PN_PROFILE}" \
	  -D CMAKE_SHARED_LINKER_FLAGS="-fuse-ld=lld -Wl,-mllvm,-preserve-none-enable -Wl,-mllvm,-preserve-none-json=$${PN_PROFILE}" \
	  -D CMAKE_MODULE_LINKER_FLAGS="-fuse-ld=lld -Wl,-mllvm,-preserve-none-enable -Wl,-mllvm,-preserve-none-json=$${PN_PROFILE}"
	@ninja -j "$(JOBS)" -C "$(PN_THINLTO_FDO_DIR)" && \
	touch $@ && \
	$(call log,✅ pn_thinlto_fdo_clang built successfully.)

fdo_liveness_analysis: 
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
		-D CMAKE_C_FLAGS="-mllvm -enable-cs-reg-liveness-analysis -mllvm -cs-reg-liveness-analysis-output-dir=$(FDO_LIVENESS_OUTPUT_DIR) -mllvm -enable-ipra-prera-analysis -mllvm -ipra-dry-run -mllvm -ipra-prera-analysis-output-dir=$(FDO_LIVENESS_OUTPUT_DIR)" \
		-D CMAKE_CXX_FLAGS="-mllvm -enable-cs-reg-liveness-analysis -mllvm -cs-reg-liveness-analysis-output-dir=$(FDO_LIVENESS_OUTPUT_DIR) -mllvm -enable-ipra-prera-analysis -mllvm -ipra-dry-run -mllvm -ipra-prera-analysis-output-dir=$(FDO_LIVENESS_OUTPUT_DIR)"
	@ninja -j "$(JOBS)" -C "$$TEMP_LLD_BUILD_DIR" lld
	@rm -rf "$$TEMP_LLD_BUILD_DIR"
	@$(call log,✅ Liveness Data collected in $(FDO_LIVENESS_OUTPUT_DIR))

thinlto_fdo_liveness_analysis: 
	@$(call log,Collecting Liveness Data using thinlto_fdo_clang)
	@mkdir -p "$(THINLTO_FDO_LIVENESS_OUTPUT_DIR)"
	@TEMP_CLANG_BUILD_DIR="$(DEV_DIR)/temp_clang_for_liveness_analysis"
	@rm -rf "$$TEMP_CLANG_BUILD_DIR"
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$$TEMP_CLANG_BUILD_DIR" \
		-D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
		-D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
		-D CMAKE_BUILD_TYPE=Release \
		-D LLVM_ENABLE_PROJECTS=clang \
		-D LLVM_TARGETS_TO_BUILD=X86 \
		-D LLVM_PROFDATA_FILE="$(PROFILE_MERGED_FILE)" \
		-D LLVM_ENABLE_LTO=Thin \
	  	-D LLVM_USE_LINKER=lld \
		-D CMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld -Wl,-mllvm,-enable-cs-reg-liveness-analysis -Wl,-mllvm,-cs-reg-liveness-analysis-output-dir=$(THINLTO_FDO_LIVENESS_OUTPUT_DIR) -Wl,-mllvm,-enable-ipra-prera-analysis -Wl,-mllvm,-ipra-dry-run -Wl,-mllvm,-ipra-prera-analysis-output-dir=$(THINLTO_FDO_LIVENESS_OUTPUT_DIR)" \
	    -D CMAKE_SHARED_LINKER_FLAGS="-fuse-ld=lld -Wl,-mllvm,-enable-cs-reg-liveness-analysis -Wl,-mllvm,-cs-reg-liveness-analysis-output-dir=$(THINLTO_FDO_LIVENESS_OUTPUT_DIR) -Wl,-mllvm,-enable-ipra-prera-analysis -Wl,-mllvm,-ipra-dry-run -Wl,-mllvm,-ipra-prera-analysis-output-dir=$(THINLTO_FDO_LIVENESS_OUTPUT_DIR)" \
	    -D CMAKE_MODULE_LINKER_FLAGS="-fuse-ld=lld -Wl,-mllvm,-enable-cs-reg-liveness-analysis -Wl,-mllvm,-cs-reg-liveness-analysis-output-dir=$(THINLTO_FDO_LIVENESS_OUTPUT_DIR) -Wl,-mllvm,-enable-ipra-prera-analysis -Wl,-mllvm,-ipra-dry-run -Wl,-mllvm,-ipra-prera-analysis-output-dir=$(THINLTO_FDO_LIVENESS_OUTPUT_DIR)"
	@ninja -j "$(JOBS)" -C "$$TEMP_CLANG_BUILD_DIR"
	@rm -rf "$$TEMP_CLANG_BUILD_DIR"
	@$(call log,✅ Liveness Data collected in $(THINLTO_FDO_LIVENESS_OUTPUT_DIR));

ipra_thinlto_fdo_liveness_analysis:
	@$(call log,Collecting Liveness Data using thinlto_fdo_clang)
	@mkdir -p "$(IPRA_THINLTO_FDO_LIVENESS_OUTPUT_DIR)"
	@TEMP_CLANG_BUILD_DIR="$(DEV_DIR)/temp_clang_for_liveness_analysis"
	@rm -rf "$$TEMP_CLANG_BUILD_DIR";

	LFLAGS="-fuse-ld=lld -Wl,-mllvm,-enable-ipra -Wl,-mllvm,-enable-cs-reg-liveness-analysis -Wl,-mllvm,-cs-reg-liveness-analysis-output-dir=$(IPRA_THINLTO_FDO_LIVENESS_OUTPUT_DIR) -Wl,-mllvm,-enable-ipra-prera-analysis -Wl,-mllvm,-ipra-dry-run -Wl,-mllvm,-ipra-prera-analysis-output-dir=$(IPRA_THINLTO_FDO_LIVENESS_OUTPUT_DIR)"
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$$TEMP_CLANG_BUILD_DIR" \
		-D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
		-D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
		-D CMAKE_BUILD_TYPE=Release \
		-D LLVM_ENABLE_PROJECTS=clang \
		-D LLVM_TARGETS_TO_BUILD=X86 \
		-D LLVM_PROFDATA_FILE="$(PROFILE_MERGED_FILE)" \
		-D LLVM_ENABLE_LTO=Thin \
	  	-D LLVM_USE_LINKER=lld \
		-D CMAKE_EXE_LINKER_FLAGS="$${LFLAGS}" \
	    -D CMAKE_SHARED_LINKER_FLAGS="$${LFLAGS}" \
	    -D CMAKE_MODULE_LINKER_FLAGS="$${LFLAGS}"
	@ninja -j "$(JOBS)" -C "$$TEMP_CLANG_BUILD_DIR"
	@rm -rf "$$TEMP_CLANG_BUILD_DIR"
	@$(call log,✅ Liveness Data collected in $(IPRA_THINLTO_FDO_LIVENESS_OUTPUT_DIR));

# --- AutoFDO Build Targets ---
# Step 1: Build clang with AutoFDO metadata flags
autofdo_metadata_clang:
	$(call log,STEP AFDO-1: Building autofdo_metadata_clang (Release build with AutoFDO flags))
	cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(AUTOFDO_METADATA_DIR)" \
		-D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
		-D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
		-D CMAKE_BUILD_TYPE=Release \
		-D LLVM_ENABLE_PROJECTS="clang;lld" \
		-D LLVM_TARGETS_TO_BUILD=X86 \
		-D LLVM_ENABLE_RUNTIMES="compiler-rt" \
		-D LLVM_ENABLE_LTO=Thin \
		-D CMAKE_C_FLAGS="-gmlt -fdebug-info-for-profiling -mllvm -enable-fs-discriminator=true -mllvm -improved-fs-discriminator=true" \
		-D CMAKE_CXX_FLAGS="-gmlt -fdebug-info-for-profiling -mllvm -enable-fs-discriminator=true -mllvm -improved-fs-discriminator=true" \
		-D LLVM_USE_LINKER=lld \
		-D CMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld -Wl,--mllvm=-enable-fs-discriminator=true -Wl,--mllvm=-improved-fs-discriminator=true -Wl,--build-id" \
		-D CMAKE_SHARED_LINKER_FLAGS="-fuse-ld=lld -Wl,--mllvm=-enable-fs-discriminator=true -Wl,--mllvm=-improved-fs-discriminator=true -Wl,--build-id" \
		-D CMAKE_MODULE_LINKER_FLAGS="-fuse-ld=lld -Wl,--mllvm=-enable-fs-discriminator=true -Wl,--mllvm=-improved-fs-discriminator=true -Wl,--build-id"
	ninja -j "$(JOBS)" -C "$(AUTOFDO_METADATA_DIR)"
	@touch $@
	$(call log,✅ autofdo_metadata_clang built successfully.)

# Step 2: Collect perf profile data using the metadata clang
# (This target just defines the file, it's run by the next target)
autofdo_collect_perf:
	@$(call log, Collecting perf profile data)
	@set -e; \
	perf record -e BR_INST_RETIRED.NEAR_TAKEN:u -b -c 500009 \
		-o "$(AUTOFDO_PERF_FILE)" -- \
		/usr/local/google/home/tanjihui/Desktop/clangbench/do-clangbench.sh \
			run_local \
			--cc "$(AUTOFDO_METADATA_DIR)/bin/clang++" \
			--iterations 1; \
	$(call log,✅ Perf data collected at $(AUTOFDO_PERF_FILE))

# Step 3: Convert perf data to LLVM profile format
autofdo_convert_profile:
	$(call log, Converting perf data to LLVM profile)
	./create_llvm_prof --binary="$(AUTOFDO_METADATA_DIR)/bin/clang++" \
					 --profile="$(AUTOFDO_PERF_FILE)" \
					 --format=extbinary \
					 --out="$(AUTOFDO_PROFILE_FILE)"
	$(call log,✅ LLVM profile created at $(AUTOFDO_PROFILE_FILE))

# Step 4: Build the final ThinLTO + AutoFDO clang
thinlto_autofdo_clang:
	@$(call log, Building thinlto_autofdo_clang (ThinLTO + AutoFDO optimized build))
	BUILD_TYPE=$${BUILD_TYPE:-Release};
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(THINLTO_AUTOFDO_DIR)" \
		-D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
		-D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
		-D CMAKE_BUILD_TYPE=$${BUILD_TYPE} \
		-D LLVM_ENABLE_PROJECTS=clang \
		-D LLVM_TARGETS_TO_BUILD=X86 \
		-D LLVM_ENABLE_LTO=Thin \
		-D LLVM_USE_LINKER=lld \
		-D CMAKE_C_FLAGS="-gmlt -fdebug-info-for-profiling -mllvm -enable-fs-discriminator=true -mllvm -improved-fs-discriminator=true -fprofile-sample-use=$(AUTOFDO_PROFILE_FILE) -ffunction-sections -fdata-sections" \
		-D CMAKE_CXX_FLAGS="-gmlt -fdebug-info-for-profiling -mllvm -enable-fs-discriminator=true -mllvm -improved-fs-discriminator=true -fprofile-sample-use=$(AUTOFDO_PROFILE_FILE) -ffunction-sections -fdata-sections" \
		-D CMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld -Wl,--mllvm=-enable-fs-discriminator=true -Wl,--mllvm=-improved-fs-discriminator=true -Wl,--lto-sample-profile=$(AUTOFDO_PROFILE_FILE)" \
		-D CMAKE_SHARED_LINKER_FLAGS="-fuse-ld=lld -Wl,--mllvm=-enable-fs-discriminator=true -Wl,--mllvm=-improved-fs-discriminator=true -Wl,--lto-sample-profile=$(AUTOFDO_PROFILE_FILE)" \
		-D CMAKE_MODULE_LINKER_FLAGS="-fuse-ld=lld -Wl,--mllvm=-enable-fs-discriminator=true -Wl,--mllvm=-improved-fs-discriminator=true -Wl,--lto-sample-profile=$(AUTOFDO_PROFILE_FILE)"
	@ninja -j "$(JOBS)" -C "$(THINLTO_AUTOFDO_DIR)" && \
	touch $@ && \
	$(call log,✅ thinlto_autofdo_clang built successfully.)

thinlto_autofdo_liveness_analysis:
	@$(call log,Collecting Liveness Data using thinlto_autofdo_clang)
	BUILD_TYPE=$${BUILD_TYPE:-Release};
	@mkdir -p "$(THINLTO_AUTOFDO_LIVENESS_OUTPUT_DIR)"
	@TEMP_CLANG_BUILD_DIR="$(DEV_DIR)/temp_clang_for_liveness_analysis"
	@rm -rf "$$TEMP_CLANG_BUILD_DIR"
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$$TEMP_CLANG_BUILD_DIR" \
		-D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
		-D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
		-D CMAKE_BUILD_TYPE=$${BUILD_TYPE} \
		-D LLVM_ENABLE_PROJECTS=clang \
		-D LLVM_TARGETS_TO_BUILD=X86 \
		-D LLVM_ENABLE_LTO=Thin \
	  	-D LLVM_USE_LINKER=lld \
		-D CMAKE_C_FLAGS="-gmlt -fdebug-info-for-profiling -mllvm -enable-fs-discriminator=true -mllvm -improved-fs-discriminator=true -fprofile-sample-use=$(AUTOFDO_PROFILE_FILE) -ffunction-sections -fdata-sections" \
		-D CMAKE_CXX_FLAGS="-gmlt -fdebug-info-for-profiling -mllvm -enable-fs-discriminator=true -mllvm -improved-fs-discriminator=true -fprofile-sample-use=$(AUTOFDO_PROFILE_FILE) -ffunction-sections -fdata-sections" \
		-D CMAKE_EXE_LINKER_FLAGS="-fuse-ld=lld -Wl,--mllvm=-enable-fs-discriminator=true -Wl,--mllvm=-improved-fs-discriminator=true -Wl,--lto-sample-profile=$(AUTOFDO_PROFILE_FILE) -Wl,-mllvm,-enable-cs-reg-liveness-analysis -Wl,-mllvm,-cs-reg-liveness-analysis-output-dir=$(THINLTO_AUTOFDO_LIVENESS_OUTPUT_DIR) -Wl,-mllvm,-enable-ipra-prera-analysis -Wl,-mllvm,-ipra-dry-run -Wl,-mllvm,-ipra-prera-analysis-output-dir=$(THINLTO_AUTOFDO_LIVENESS_OUTPUT_DIR)" \
	    -D CMAKE_SHARED_LINKER_FLAGS="-fuse-ld=lld -Wl,--mllvm=-enable-fs-discriminator=true -Wl,--mllvm=-improved-fs-discriminator=true -Wl,--lto-sample-profile=$(AUTOFDO_PROFILE_FILE) -Wl,-mllvm,-enable-cs-reg-liveness-analysis -Wl,-mllvm,-cs-reg-liveness-analysis-output-dir=$(THINLTO_AUTOFDO_LIVENESS_OUTPUT_DIR) -Wl,-mllvm,-enable-ipra-prera-analysis -Wl,-mllvm,-ipra-dry-run -Wl,-mllvm,-ipra-prera-analysis-output-dir=$(THINLTO_AUTOFDO_LIVENESS_OUTPUT_DIR)" \
	    -D CMAKE_MODULE_LINKER_FLAGS="-fuse-ld=lld -Wl,--mllvm=-enable-fs-discriminator=true -Wl,--mllvm=-improved-fs-discriminator=true -Wl,--lto-sample-profile=$(AUTOFDO_PROFILE_FILE) -Wl,-mllvm,-enable-cs-reg-liveness-analysis -Wl,-mllvm,-cs-reg-liveness-analysis-output-dir=$(THINLTO_AUTOFDO_LIVENESS_OUTPUT_DIR) -Wl,-mllvm,-enable-ipra-prera-analysis -Wl,-mllvm,-ipra-dry-run -Wl,-mllvm,-ipra-prera-analysis-output-dir=$(THINLTO_AUTOFDO_LIVENESS_OUTPUT_DIR)"
	@ninja -j "$(JOBS)" -C "$$TEMP_CLANG_BUILD_DIR"
	@rm -rf "$$TEMP_CLANG_BUILD_DIR"
	@$(call log,✅ Liveness Data collected in $(THINLTO_AUTOFDO_LIVENESS_OUTPUT_DIR))\

pn_thinlto_autofdo_clang:
	@$(call log,Building pn_thinlto_autofdo_clang)
	@set -e;
	# Define the path to the JSON profile locally for this target.
	BUILD_TYPE=$${BUILD_TYPE:-Release};
	PN_PROFILE="$(THINLTO_AUTOFDO_PN_FUNCTIONS_DIR)/liveness_profdata.json";
	CFLAGS="-gmlt -fdebug-info-for-profiling -mllvm -enable-fs-discriminator=true -mllvm -improved-fs-discriminator=true -fprofile-sample-use=$(AUTOFDO_PROFILE_FILE) -ffunction-sections -fdata-sections";
	LFLAGS="-fuse-ld=lld -Wl,--mllvm=-enable-fs-discriminator=true -Wl,--mllvm=-improved-fs-discriminator=true -Wl,--lto-sample-profile=$(AUTOFDO_PROFILE_FILE) -Wl,-mllvm,-preserve-none-enable -Wl,-mllvm,-preserve-none-json=$${PN_PROFILE}";
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(PN_THINLTO_AUTOFDO_DIR)" \
      -D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
      -D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
      -D CMAKE_BUILD_TYPE=$${BUILD_TYPE} \
      -D LLVM_ENABLE_PROJECTS=clang \
      -D LLVM_TARGETS_TO_BUILD=X86 \
      -D LLVM_ENABLE_LTO=Thin \
      -D LLVM_USE_LINKER=lld \
      -D CMAKE_C_FLAGS="$${CFLAGS}" \
      -D CMAKE_CXX_FLAGS="$${CFLAGS}" \
      -D CMAKE_EXE_LINKER_FLAGS="$${LFLAGS}" \
      -D CMAKE_SHARED_LINKER_FLAGS="$${LFLAGS}" \
      -D CMAKE_MODULE_LINKER_FLAGS="$${LFLAGS}"
	@ninja -j "$(JOBS)" -C "$(PN_THINLTO_AUTOFDO_DIR)" && \
	touch $@ && \
	$(call log,✅ pn_thinlto_autofdo_clang built successfully.)

pn_thinlto_autofdo_legacy_clang:
	@$(call log,Building pn_thinlto_autofdo_clang)
	@set -e; \
	# Define the path to the JSON profile locally for this target.
	BUILD_TYPE=$${BUILD_TYPE:-Release};
	PN_SYMS_FILE="$(THINLTO_AUTOFDO_LIVENESS_OUTPUT_DIR)/pn.syms";
	PN_CFLAGS="-mllvm -enable-ipra-prera-analysis -mllvm -ipra-prera-function-syms-file=$${PN_SYMS_FILE}"; \
	PN_LFLAGS="-Wl,-mllvm,-enable-ipra-prera-analysis -Wl,-mllvm,-ipra-prera-function-syms-file=$${PN_SYMS_FILE}";
	CFLAGS="-gmlt -fdebug-info-for-profiling -mllvm -enable-fs-discriminator=true -mllvm -improved-fs-discriminator=true -fprofile-sample-use=$(AUTOFDO_PROFILE_FILE) -ffunction-sections -fdata-sections"; \
	LFLAGS="-fuse-ld=lld -Wl,--mllvm=-enable-fs-discriminator=true -Wl,--mllvm=-improved-fs-discriminator=true -Wl,--lto-sample-profile=$(AUTOFDO_PROFILE_FILE)";
	@cmake -G Ninja -S "$(LLVM_SRC_DIR)/llvm" -B "$(PN_THINLTO_AUTOFDO_LEGACY_DIR)" \
	  -D CMAKE_C_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang" \
	  -D CMAKE_CXX_COMPILER="$(BOOTSTRAPPED_DIR)/bin/clang++" \
	  -D CMAKE_BUILD_TYPE=$${BUILD_TYPE} \
	  -D LLVM_ENABLE_PROJECTS=clang \
	  -D LLVM_TARGETS_TO_BUILD=X86 \
	  -D LLVM_ENABLE_LTO=Thin \
	  -D LLVM_USE_LINKER=lld \
	  -D CMAKE_C_FLAGS="$${CFLAGS} $${PN_CFLAGS}" \
	  -D CMAKE_CXX_FLAGS="$${CFLAGS} $${PN_CFLAGS}" \
	  -D CMAKE_EXE_LINKER_FLAGS="$${LFLAGS} $${PN_LFLAGS}" \
	  -D CMAKE_SHARED_LINKER_FLAGS="$${LFLAGS} $${PN_LFLAGS}" \
	  -D CMAKE_MODULE_LINKER_FLAGS="$${LFLAGS} $${PN_LFLAGS}"
	@ninja -j "$(JOBS)" -C "$(PN_THINLTO_AUTOFDO_LEGACY_DIR)" && \
	touch $@ && \
	$(call log,✅ pn_thinlto_autofdo_clang built successfully.)

test_pn_thinlto_autofdo_clang:
	@$(MAKE) rebuild COMPILER=pn_thinlto_autofdo_clang
	@$(MAKE) benchmark COMPILER=pn_thinlto_autofdo_clang

rebuild:
	# Rebuild bootstrapped_clang
	@$(MAKE) bootstrapped_clang

	@if [ -z "$(COMPILER)" ]; then \
		echo "Rebuild bootstrapped_clang done."; \
		echo "If you want to rebuild opt clang: make rebuild COMPILER=<name>"; \
		exit 0; \
	fi

	VAR_BASE_NAME=$$(echo $(COMPILER) | tr '[:lower:]' '[:upper:]' | sed 's/_CLANG$$//'); \
	DIR_VAR_NAME="$${VAR_BASE_NAME}_DIR";
	COMPILER_DIR=$$( $(MAKE) -s --no-print-directory -f $(lastword $(MAKEFILE_LIST)) print-var VARNAME=$$DIR_VAR_NAME ); \

	# Rebuild specified opt clang
	@rm -rf $${COMPILER_DIR}
	@rm $(COMPILER)
	@$(MAKE) $(COMPILER)

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
	DIR_VAR_NAME="$${VAR_BASE_NAME}_DIR"; \
	\
	# Dynamically get the VALUE of the make variables by recursively calling make.
	COMPILER_DIR=$$( $(MAKE) -s --no-print-directory -f $(lastword $(MAKEFILE_LIST)) print-var VARNAME=$$DIR_VAR_NAME ); \
	\
	$(call log,Starting benchmark for '$(COMPILER)'); \
	\
	BENCHMARK_RUNS=$${BENCHMARK_RUNS:-1}; \
	TEMP_BUILD_DIR="$(DEV_DIR)/temp_benchmark_build_$(COMPILER)"; \
	METRICS_CSV="$(METRICS_DIR)/references/benchmark_results/$(COMPILER)_metrics.csv"; \
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

size:
	@if [ -z "$(COMPILER)" ]; then \
	echo "Error: You must specify which compiler to benchmark."; \
	echo "Usage: make benchmark COMPILER=<name>"; \
	exit 1; \
	fi

	@set -e; \
	\
	# Dynamically construct the variable names based on the COMPILER input.
	VAR_BASE_NAME=$$(echo $(COMPILER) | tr '[:lower:]' '[:upper:]' | sed 's/_CLANG$$//'); \
	DIR_VAR_NAME="$${VAR_BASE_NAME}_DIR"; \
	\
	# Dynamically get the VALUE of the make variables by recursively calling make.
	COMPILER_DIR=$$( $(MAKE) -s --no-print-directory -f $(lastword $(MAKEFILE_LIST)) print-var VARNAME=$$DIR_VAR_NAME ); \

	@size $${COMPILER_DIR}/bin/clang;
