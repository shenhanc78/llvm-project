#!/bin/bash
#
# run-benchmark.sh: Wrapper script to run individual MySQL sysbench functions.
#
# Usage:
#   ./run-benchmark.sh <build_dir> <function_to_run> [args...]
#

set -e

if [[ "$#" -lt 2 ]]; then
    echo "Usage: $0 <build_dir> <function_to_run> [args...]"
    exit 1
fi

# --- Configuration ---
BUILD_DIR_ABS=$(cd "$1" && pwd)
RUN_MODE="$2"
shift 2 # All remaining args are passed to the function
ARGS=("$@")

# Get base paths
CUR_DIR=$(cd "$(dirname "$0")" && pwd)
DEV_DIR=$(cd "${CUR_DIR}/../../../../ipra-run" && pwd)
SOURCE_BASE_DIR="${DEV_DIR}/mysql_benchmark/source"

# Script containing the run functions
MYSQL_RUN_FUNCS_PATH="${CUR_DIR}/mysql-run-funcs.sh"
if [ ! -f "$MYSQL_RUN_FUNCS_PATH" ]; then
    echo "Error: mysql-run-funcs.sh not found at ${MYSQL_RUN_FUNCS_PATH}"
    exit 1
fi

# Paths for the run
INSTALL_DIR="${BUILD_DIR_ABS}/install"
BENCH_DIR="${BUILD_DIR_ABS}/bench.dir" # Working directory for benchmark
MYSQL_DATA_DIR="data.dir" # Subdirectory within BENCH_DIR

# --- Minimal logging for helper scripts ---
if [[ "$RUN_MODE" != "loadtest" && "$RUN_MODE" != "benchmark" ]]; then
    echo "--- MySQL Helper ---"
    echo "  Mode: ${RUN_MODE}"
fi

# Create and move into the benchmark directory
mkdir -p "${BENCH_DIR}"
cd "${BENCH_DIR}"

# The run functions in mysql-run-funcs.sh expect 'install.dir' to be present
# in the current directory, pointing to the MySQL installation.
ln -sfn "${INSTALL_DIR}" install.dir

# Source the functions *after* changing into the correct directory,
# so the 'current_run_pwd=$(pwd)' variable inside it is set correctly.
source "${MYSQL_RUN_FUNCS_PATH}"

# --- Run Workload ---
# Dynamically call the function passed as RUN_MODE,
# passing MYSQL_DATA_DIR as the first arg, and any other args after.
"${RUN_MODE}" "${MYSQL_DATA_DIR}" "${ARGS[@]}"