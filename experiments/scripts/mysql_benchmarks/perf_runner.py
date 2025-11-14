import subprocess
import sys
import os
import datetime
import shutil

# --- Configuration ---
NUM_RUNS = 10
TARGETS = {
    "PreserveNone_MySQL": {
        "build_dir": "../../../../ipra-run/mysql_benchmark/thinlto_autofdo_mysql",
    },
    "Baseline_MySQL": {
        "build_dir": "../../../../ipra-run/mysql_benchmark/thinlto_autofdo_mysql",
    }
}

# --- This is the workload definition ---
SYSBENCH_WORKLOAD = [
    {
        "name": "oltp_read_write",
        "prepare_cmd": ["prepare_oltp_rw"],
        "run_cmd": ["run_oltp_rw", "1"], # Iterations is 1, perf_runner loops
        "cleanup_cmd": ["cleanup_oltp_rw"]
    },
    {
        "name": "oltp_update_index",
        "prepare_cmd": ["prepare_oltp_ui"],
        "run_cmd": ["run_oltp_ui", "1"],
        "cleanup_cmd": ["cleanup_oltp_ui"]
    },
    {
        "name": "oltp_delete",
        "prepare_cmd": ["prepare_oltp_del"],
        "run_cmd": ["run_oltp_del", "1"],
        "cleanup_cmd": ["cleanup_oltp_del"]
    },
    {
        "name": "select_random_ranges",
        "prepare_cmd": ["prepare_select_rr"],
        "run_cmd": ["run_select_rr", "1"],
        "cleanup_cmd": ["cleanup_select_rr"]
    },
    {
        "name": "oltp_read_only",
        "prepare_cmd": ["prepare_oltp_ro"],
        "run_cmd": ["run_oltp_ro", "1"],
        "cleanup_cmd": ["cleanup_oltp_ro"]
    }
]

# Copy json prof_data for documentation
JSON_SRC_FILE = '../../metrics/pn_functions/thinlto_autofdo_mysql_pn_functions/liveness_profdata.json'
BASE_DIR = f"../../metrics/references/mysql_results/"
PERF_EVENTS = "instructions,cycles,L1-icache-load-misses,iTLB-load-misses"
# ---------------------

def run_helper_script(build_dir, task_name, args_list=None, capture=True, timeout=300):
    """Helper to run a task, exiting on failure."""
    if args_list is None:
        args_list = []
    
    command = ["./run-benchmark.sh", build_dir, task_name] + args_list
    try:
        result = subprocess.run(
            command,
            check=True,
            capture_output=capture,
            text=True,
            timeout=timeout
        )
        return result
            
    except subprocess.CalledProcessError as e:
        print(f"\n❌ ERROR: Failed to run '{task_name}' for {build_dir}")
        print("\n--- STDOUT ---")
        print(e.stdout)
        print("\n--- STDERR ---")
        print(e.stderr)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"\n❌ ERROR: Timeout during '{task_name}' for {build_dir}")
        sys.exit(1)


def setup_databases_once():
    """
    Runs the one-time database initialization for each target.
    """
    print("="*80)
    print("🚀 Starting One-Time Database Setup (mysqld --initialize-insecure)")
    print("This may take a minute...")
    
    for name, config in TARGETS.items():
        build_dir = config["build_dir"]
        
        print(f"--- Initializing DB for [{name}] in {build_dir}")
        data_dir = os.path.join(build_dir, "bench.dir", "data.dir")
        if os.path.exists(data_dir) and len(os.listdir(data_dir)) > 0:
             print(f"ℹ️ Database directory already exists. Skipping 'setup_db'.")
        else:
            run_helper_script(build_dir, "setup_db")
            print(f"✅ DB for [{name}] initialized successfully.")
            
    print("✅ All databases initialized successfully.")
    print("="*80 + "\n")


def run_benchmark():
    # --- Run one-time setup first ---
    setup_databases_once()

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
    for name in TARGETS.keys():
        sanitized_name = name.replace(" ", "_")
        benchmark_dir = os.path.join(base_results_dir, sanitized_name)
        os.makedirs(benchmark_dir, exist_ok=True)
        benchmark_dirs[name] = benchmark_dir
        print(f"    -> {benchmark_dir}")

    print("\n" + "="*80)
    print("🚀 Starting Formal Benchmark Runs (Batched)")
    
    # --- Loop by command FIRST, then by run number (Batched) ---
    for name, config in TARGETS.items():
        print(f"🚀 Starting Batch for [{name}] ({NUM_RUNS} runs)")
        
        build_dir = config["build_dir"]
        results_dir = benchmark_dirs[name]
        
        for i in range(1, NUM_RUNS + 1):
            
            output_file = os.path.join(results_dir, f"run_{i}.txt")
            run_log_stdout = ""
            run_log_stderr = ""
            
            try:
                # --- 1. START SERVER (un-timed) ---
                print(f"--- Running [{name}] Iteration {i} of {NUM_RUNS}... (Starting server...)", end="", flush=True)
                run_helper_script(build_dir, "start_server")

                # --- 2. CREATE DATABASE (un-timed) ---
                print(" (Creating DB...)", end="", flush=True)
                run_helper_script(build_dir, "create_database")

                # --- 3. RUN WORKLOAD (The core timed loop) ---
                for test in SYSBENCH_WORKLOAD:
                    test_name = test['name']
                    print(f"\n    > {test_name}: (Prepare...)", end="", flush=True)
                    # 3a. PREPARE (un-timed)
                    run_helper_script(build_dir, test["prepare_cmd"][0], test["prepare_cmd"][1:])

                    # 3b. RUN (timed)
                    print(" (Run...)", end="", flush=True)
                    
                    # --- This is the command that will be timed ---
                    run_command_list = ["./run-benchmark.sh", build_dir] + test["run_cmd"]
                    
                    perf_command = [
                        "perf", "stat", "-e", PERF_EVENTS,
                        "--"] + run_command_list
                    
                    result = subprocess.run(perf_command, check=True, capture_output=True, text=True, timeout=600)
                    
                    # Store stdout (sysbench log) and stderr (perf log)
                    run_log_stdout += f"\n--- Output for {test_name} ---\n{result.stdout.strip()}\n"
                    run_log_stderr += f"\n--- Perf for {test_name} ---\n{result.stderr.strip()}\n"

                    # 3c. CLEANUP (un-timed)
                    print(" (Cleanup...)", end="", flush=True)
                    run_helper_script(build_dir, test["cleanup_cmd"][0], test["cleanup_cmd"][1:])

                # --- 4. STOP SERVER (un-timed) ---
                print("\n    > (Stopping server...)", end="", flush=True)
                run_helper_script(build_dir, "stop_server")

                # Write the combined captured output
                with open(output_file, 'w') as f:
                    f.write(f"Results for Benchmark: {name} - Run {i}\n")
                    f.write("="*40 + "\n\n")
                    f.write("--- Script Output (stdout) ---\n")
                    f.write(run_log_stdout + "\n\n")
                    f.write("--- Perf Report (stderr) ---\n")
                    f.write(run_log_stderr + "\n")

                print(f" ✅ Done. Results saved to: {output_file}")

            except FileNotFoundError:
                print(f"❌ Error: 'perf' not found. Is it installed and in your PATH?")
                sys.exit(1)
            except subprocess.CalledProcessError as e:
                print(f"❌ Error: Command failed with exit code {e.returncode}")
                with open(output_file, 'w') as f:
                    f.write(f"### ERROR during Benchmark: {name} - Run {i} ###\n\n")
                    if e.stdout: f.write("--- Stdout ---\n" + e.stdout.strip() + "\n\n")
                    if e.stderr: f.write("--- Stderr ---\n" + e.stderr.strip() + "\n")
                print(f"🔥 Error details saved to: {output_file}")
                try: run_helper_script(build_dir, "stop_server")
                except: pass
            except subprocess.TimeoutExpired:
                 print(f"❌ Error: Command timed out.")
                 with open(output_file, 'w') as f:
                    f.write(f"### ERROR: Timeout during Benchmark: {name} - Run {i} ###\n\n")
                 try: run_helper_script(build_dir, "stop_server")
                 except: pass
        
        print(f"--- Batch for [{name}] complete ---")
        print("-" * 80) # Add a separator between batches

    print("\n\n🎉 All benchmark runs complete.")
    print(f"\n✅ Analyze the results with:")
    print(f"python3 perf_analyzer.py {base_results_dir}")


if __name__ == "__main__":
    run_benchmark()