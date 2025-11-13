import subprocess
import sys
import os
import datetime
import shutil

# --- Configuration ---
NUM_RUNS = 10
COMMANDS = {
    # Key name will be used for the directory, e.g., "Baseline_MySQL"
    "PreserveNone_MySQL": [
        "./run-benchmark.sh",
        "../../../../ipra-run/mysql_benchmark/pn_thinlto_autofdo_mysql",
        "benchmark",
        "1"
    ],
    "Baseline_MySQL": [
        "./run-benchmark.sh",
        "../../../../ipra-run/mysql_benchmark/thinlto_autofdo_mysql",
        "benchmark",
        "1" # We run 1 iteration; this script loops NUM_RUNS times
    ]
}

# Copy json prof_data for documentation
# Paths are relative to mysql_benchmarks/
JSON_SRC_FILE = '../../metrics/pn_functions/thinlto_autofdo_mysql_pn_functions/liveness_profdata.json'
BASE_DIR = f"../../metrics/references/mysql_results/"
# ---------------------

def setup_databases():
    """
    Runs the one-time database initialization for each target.
    This is done *outside* of the main perf stat loop.
    """
    print("="*80)
    print("🚀 Starting One-Time Database Setup (mysqld --initialize-insecure)")
    print("This may take a minute...")
    
    for name, command_list in COMMANDS.items():
        # [./run-benchmark.sh, <build_dir>, "benchmark", "1"]
        build_dir = command_list[1]
        setup_command = ["./run-benchmark.sh", build_dir, "setup_db"]
        
        print(f"--- Initializing DB for [{name}] in {build_dir}")
        try:
            subprocess.run(setup_command, check=True, capture_output=True, text=True)
            print(f"✅ DB for [{name}] initialized successfully.")
        except subprocess.CalledProcessError as e:
            print(f"❌ ERROR: Failed to setup database for [{name}]")
            print(e.stderr)
            sys.exit(1)
            
    print("✅ All databases initialized successfully.")
    print("="*80 + "\n")


def run_benchmark():
    # --- NEW: Run one-time setup first ---
    setup_databases()

    # Create a unique, timestamped directory for this entire benchmark session
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    base_results_dir = f"{BASE_DIR}mysql_results_{timestamp}"
    os.makedirs(base_results_dir, exist_ok=True)
    print(f"📂 Saving all results to: {base_results_dir}\n")
    
    if os.path.exists(JSON_SRC_FILE):
        print('📂 For record, documenting liveness_profdata.json...')
        shutil.copy(JSON_SRC_FILE, base_results_dir)
    else:
        print(f"ℹ️ Note: Liveness profile not found at {JSON_SRC_FILE}, skipping copy.")


    # --- Create all benchmark-specific directories first ---
    benchmark_dirs = {}
    print("Pre-creating result directories:")
    for name in COMMANDS.keys():
        # Sanitize the name to be filesystem-friendly
        sanitized_name = name.replace(" ", "_")
        benchmark_dir = os.path.join(base_results_dir, sanitized_name)
        os.makedirs(benchmark_dir, exist_ok=True)
        benchmark_dirs[name] = benchmark_dir
        print(f"    -> {benchmark_dir}")


    print("\n" + "="*80)
    print("🚀 Starting Formal Benchmark Runs")
    
    # --- Loop by run number FIRST, then by command ---
    for name, command_list in COMMANDS.items():
        for i in range(1, NUM_RUNS + 1):
            print(f"🚀 Starting Global Iteration {i} of {NUM_RUNS}")
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
                # Don't exit, just continue to the next iteration
        
        print("-" * 80) # Add a separator between iterations

    print("\n\n🎉 All benchmark runs complete.")


if __name__ == "__main__":
    run_benchmark()