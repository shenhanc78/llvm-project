#!/bin/bash
#
# parse-results.sh: Parses sysbench output files and calculates stats.
#
# Usage:
#   ./parse-results.sh <build_dir> <iterations>
#

set -e

if [[ "$#" -ne 2 ]]; then
    echo "Usage: $0 <build_dir> <iterations>"
    exit 1
fi

BUILD_DIR_ABS=$(cd "$1" && pwd)
ITERATIONS="$2"
BENCH_DIR="${BUILD_DIR_ABS}/bench.dir"

if [ ! -d "$BENCH_DIR" ]; then
    echo "Error: Benchmark directory not found: ${BENCH_DIR}"
    exit 1
fi

cd "${BENCH_DIR}"

benchmarks=( select_random_ranges oltp_delete oltp_read_only oltp_read_write oltp_update_index )

# Header for the CSV
echo "Benchmark,Metric,Average,StdDev"

for bn in "${benchmarks[@]}"; do
    # Calculate stats for TransactionsPerSec
    cat "sysbench.${bn}.transPerSec" | awk -v bn="$bn" '
        {
            sum += $1;
            sumsq += $1 * $1;
        }
        END {
            if (NR > 0) {
                avg = sum / NR;
                stddev = sqrt((sumsq - (sum * sum) / NR) / NR); # Sample stddev
                if (NR == 1) stddev = 0;
                printf "%s,TransactionsPerSec,%.2f,%.2f\n", bn, avg, stddev;
            } else {
                printf "%s,TransactionsPerSec,0.00,0.00\n", bn;
            }
        }'

    # Calculate stats for Time
    cat "sysbench.${bn}.time" | awk -v bn="$bn" '
        {
            sum += $1;
            sumsq += $1 * $1;
        }
        END {
            if (NR > 0) {
                avg = sum / NR;
                stddev = sqrt((sumsq - (sum * sum) / NR) / NR); # Sample stddev
                if (NR == 1) stddev = 0;
                printf "%s,TotalTime_s,%.3f,%.3f\n", bn, avg, stddev;
            } else {
                printf "%s,TotalTime_s,0.000,0.000\n", bn;
            }
        }'
done