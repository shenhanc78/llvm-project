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
        "/usr/local/google/home/tanjihui/ipra-run/pn_thinlto_autofdo_clang/bin/clang++",
        "--iterations",
        "1"
    ],
    "ThinLTO FDO": [
        "/usr/local/google/home/tanjihui/Desktop/clangbench/do-clangbench.sh",
        "run_local",
        "--cc",
        "/usr/local/google/home/tanjihui/ipra-run/thinlto_autofdo_clang/bin/clang++",
        "--iterations",
        "1"
    ]
}
# Copy json prof_data for documentations
JSON_SRC_FILE = '../metrics/pn_functions/thinlto_autofdo_pn_functions/liveness_profdata.json'
BASE_DIR = f"../metrics/references/clangbench_results/"
# ---------------------
def run_benchmark():
    """
    Runs benchmarks in an interleaved fashion:
    Run 1 (A), Run 1 (B), Run 2 (A), Run 2 (B), ...
    """
    # Create a unique, timestamped directory for this entire benchmark session
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    base_results_dir = f"{BASE_DIR}clangbench_results_{timestamp}"
    os.makedirs(base_results_dir, exist_ok=True)
    print(f"📂 Saving all results to: {base_results_dir}\n")
    print('📂 For record, documenting liveness_profdata.json...')
    shutil.copy(JSON_SRC_FILE, base_results_dir)

    # --- NEW: Create all benchmark-specific directories first ---
    benchmark_dirs = {}
    print("Pre-creating result directories:")
    for name in COMMANDS.keys():
        # Sanitize the name to be filesystem-friendly
        sanitized_name = name.replace(" ", "_")
        benchmark_dir = os.path.join(base_results_dir, sanitized_name)
        os.makedirs(benchmark_dir, exist_ok=True)
        benchmark_dirs[name] = benchmark_dir
        print(f"   -> {benchmark_dir}")


    print("\n" + "="*80)
    
    # --- MODIFIED: Loop by run number FIRST, then by command ---
    for i in range(1, NUM_RUNS + 1):
        print(f"🚀 Starting Global Iteration {i} of {NUM_RUNS}")

        for name, command_list in COMMANDS.items():
            # Get the pre-made directory for this benchmark
            benchmark_dir = benchmark_dirs[name]
            
            # Define the full path for the output file
            output_file = os.path.join(benchmark_dir, f"run_{i}.txt")
            
            print(f"--- Running [{name}]... ", end="", flush=True)

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
        
        print("-" * 80) # Add a separator between iterations

    print("\n\n🎉 All benchmark runs complete.")


if __name__ == "__main__":
    run_benchmark()