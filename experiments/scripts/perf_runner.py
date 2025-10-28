import subprocess
import sys
import os
import datetime
import shutil

# --- Configuration ---
NUM_RUNS = 10
COMMANDS = {
    "Preserve None": [
        "/usr/local/google/home/tanjihui/Desktop/clangbench/do-clangbench.sh",
        "run_local",
        "--cc",
        "/usr/local/google/home/tanjihui/ipra-run/pn_ipra_thinlto_fdo_clang/bin/clang++",
        "--iterations",
        "1"
    ],
    "ThinLTO FDO": [
        "/usr/local/google/home/tanjihui/Desktop/clangbench/do-clangbench.sh",
        "run_local",
        "--cc",
        "/usr/local/google/home/tanjihui/ipra-run/thinly_linked_fdo_clang/bin/clang++",
        "--iterations",
        "1"
    ]
}
# Copy json prof_data for documentations
JSON_SRC_FILE = '../metrics/thinly_linked_fdo_liveness_output/liveness_profdata.json'
# ---------------------


def run_benchmark():
    """Iterates through commands, runs them with perf, and saves output to files."""
    # Create a unique, timestamped directory for this entire benchmark session
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    base_results_dir = f"../metrics/references/benchmark_results/benchmark_results_{timestamp}"
    os.makedirs(base_results_dir, exist_ok=True)
    print(f"📂 Saving all results to: {base_results_dir}\n")
    print('📂 For record, documenting liveness_profdata.json...')
    shutil.copy(JSON_SRC_FILE, base_results_dir)

    for name, command_list in COMMANDS.items():
        print("="*80)
        print(f"🚀 Starting Benchmark: {name}")
        
        # Create a subdirectory for this specific benchmark's results
        # Sanitize the name to be filesystem-friendly
        sanitized_name = name.replace(" ", "_")
        benchmark_dir = os.path.join(base_results_dir, sanitized_name)
        os.makedirs(benchmark_dir, exist_ok=True)
        
        for i in range(1, NUM_RUNS + 1):
            # Define the full path for the output file
            output_file = os.path.join(benchmark_dir, f"run_{i}.txt")
            
            print(f"--- Running [{name}] Iteration {i} of {NUM_RUNS}... ", end="", flush=True)

            perf_command = ["perf", "stat", "-e instructions,cycles,L1-icache-load-misses,iTLB-load-misses,L1-dcache-load-misses,LLC-load-misses,branch-misses", "--"] + command_list
            
            try:
                result = subprocess.run(
                    perf_command, check=True, capture_output=True, text=True
                )

                # Write the captured output to the designated file
                with open(output_file, 'w') as f:
                    f.write(f"Results for Benchmark: {name} - Run {i}\n")
                    f.write("="*40 + "\n\n")
                    if result.stdout:
                        f.write("--- Script Output (stdout) ---\n")
                        f.write(result.stdout.strip() + "\n\n")
                    if result.stderr:
                        f.write("--- Perf Report (stderr) ---\n")
                        f.write(result.stderr.strip() + "\n")

                print(f"✅ Done. Results saved to: {output_file}")

            except FileNotFoundError:
                print(f"❌ Error: 'perf' not found. Is it installed and in your PATH?")
                sys.exit(1)
            except subprocess.CalledProcessError as e:
                print(f"❌ Error: Command failed with exit code {e.returncode}")
                # Write the error to the file for later analysis
                with open(output_file, 'w') as f:
                    f.write(f"### ERROR during Benchmark: {name} - Run {i} ###\n\n")
                    if e.stdout: f.write("--- Stdout ---\n" + e.stdout.strip() + "\n\n")
                    if e.stderr: f.write("--- Stderr ---\n" + e.stderr.strip() + "\n")
                print(f"🔥 Error details saved to: {output_file}")
                sys.exit(1)

    print("\n\n🎉 All benchmark runs complete.")


if __name__ == "__main__":
    run_benchmark()