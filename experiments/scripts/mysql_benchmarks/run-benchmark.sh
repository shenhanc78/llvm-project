#!/bin/bash
#
# run-benchmark.sh: Wrapper script to run MySQL sysbench workloads.
#
# Usage:
#   ./run-benchmark.sh <build_dir> "setup_db"
#   ./run-benchmark.sh <build_dir> "loadtest"
#   ./run-benchmark.sh <build_dir> "benchmark" [iterations]
#

set -e

if [[ "$#" -lt 2 ]]; then
    echo "Usage: $0 <build_dir> \"setup_db\" | \"loadtest\" | \"benchmark\" [iterations]"
    exit 1
fi

# --- Configuration ---
BUILD_DIR_ABS=$(cd "$1" && pwd)
RUN_MODE="$2"
ITERATIONS="${3:-5}" # Default to 5 iterations for benchmark

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

echo "--- Starting MySQL Run ---"
echo "  Build: ${BUILD_DIR_ABS}"
echo "  Mode: ${RUN_MODE}"
echo "  Work Dir: ${BENCH_DIR}"
echo "  Install Dir: ${INSTALL_DIR}"

# Create and move into the benchmark directory
mkdir -p "${BENCH_DIR}"
cd "${BENCH_DIR}"

# Source the functions *after* changing into the correct directory,
# so the 'current_run_pwd=$(pwd)' variable inside it is set correctly.
source "${MYSQL_RUN_FUNCS_PATH}"

# The run functions in mysql-run-funcs.sh expect 'install.dir' to be present
# in the current directory, pointing to the MySQL installation.
ln -sfn "${INSTALL_DIR}" install.dir

# --- Run Workload ---

if [ "${RUN_MODE}" == "setup_db" ]; then
    echo "Setting up MySQL database in ${MYSQL_DATA_DIR}..."
    setup_mysql_database "${MYSQL_DATA_DIR}"
    if [[ "$?" -ne 0 ]]; then echo "*** setup_mysql_database failed ***"; exit 1; fi
    echo "--- Database Setup Complete ---"
    exit 0
fi

# --- From here on, we assume setup_db has already been run ---
# The benchmark/loadtest modes will just create the config, not init the db

echo "Starting mysqld..."
start_mysqld "${MYSQL_DATA_DIR}"
if [[ "$?" -ne 0 ]]; then echo "*** start_mysqld failed ***"; exit 1; fi

# Trap to ensure mysqld is stopped even if the script fails
trap "echo 'Stopping mysqld...'; stop_mysqld '${MYSQL_DATA_DIR}'; echo 'Stopped.'" EXIT

if [ "${RUN_MODE}" == "loadtest" ]; then
    echo "Running 'loadtest' workload (for profiling)..."
    run_sysbench_loadtest "${MYSQL_DATA_DIR}"

elif [ "${RUN_MODE}" == "benchmark" ]; then
    echo "Running 'benchmark' workload (${ITERATIONS} iterations)..."
    run_sysbench_benchmark "${MYSQL_DATA_DIR}" "${ITERATIONS}"

else
    echo "Error: Unknown run mode '${RUN_MODE}'"
    exit 1
fi

echo "--- MySQL Run Complete ---"