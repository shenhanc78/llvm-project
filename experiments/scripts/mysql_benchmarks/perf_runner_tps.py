import subprocess
import sys
import os
import datetime
import shutil
import time
from collections import defaultdict

# --- Configuration ---
NUM_RUNS = 10
TARGETS = {
    "PreserveNone_MySQL": {
        "build_dir": "../../../../ipra-run/mysql_benchmark/pn_thinlto_autofdo_mysql",
    },
    "Baseline_MySQL": {
        "build_dir": "../../../../ipra-run/mysql_benchmark/thinlto_autofdo_mysql",
    }
}

# --- Workload Definition ---
SYSBENCH_WORKLOAD = [
    {
        "name": "oltp_read_write",
        "prepare_cmd": ["prepare_oltp_rw"],
        "run_cmd": ["run_oltp_rw", "1"],
        "cleanup_cmd": ["cleanup_oltp_rw"],
        "client_core": "2" 
    },
    {
        "name": "oltp_update_index",
        "prepare_cmd": ["prepare_oltp_ui"],
        "run_cmd": ["run_oltp_ui", "1"],
        "cleanup_cmd": ["cleanup_oltp_ui"],
        "client_core": "2"
    },
    {
        "name": "oltp_delete",
        "prepare_cmd": ["prepare_oltp_del"],
        "run_cmd": ["run_oltp_del", "1"],
        "cleanup_cmd": ["cleanup_oltp_del"],
        "client_core": "2"
    },
    {
        "name": "select_random_ranges",
        "prepare_cmd": ["prepare_select_rr"],
        "run_cmd": ["run_select_rr", "1"],
        "cleanup_cmd": ["cleanup_select_rr"],
        "client_core": "2"
    },
    {
        "name": "oltp_read_only",
        "prepare_cmd": ["prepare_oltp_ro"],
        "run_cmd": ["run_oltp_ro", "1"],
        "cleanup_cmd": ["cleanup_oltp_ro"],
        "client_core": "2"
    }
]

# Copy json prof_data for documentation
JSON_SRC_FILE = '../../metrics/pn_functions/thinlto_autofdo_mysql_pn_functions/liveness_profdata.json'
BASE_DIR = f"../../metrics/references/mysql_results/"

# ---------------------

def get_mysqld_pid(build_dir):
    """Finds the PID of the ACTUAL mysqld binary and VERIFIES the path."""
    unique_data_path = os.path.join(build_dir, "bench.dir", "data.dir")
    
    MAX_WAIT_SECONDS = 30 
    print(" (Searching OS for mysqld PID)", end="", flush=True)

    for attempt in range(int(MAX_WAIT_SECONDS / 0.5)):
        try:
            pgrep_command = ["pgrep", "-f", f"mysqld.*{os.path.basename(unique_data_path)}"]
            result = subprocess.run(pgrep_command, capture_output=True, text=True, check=True, timeout=5)
            pids = result.stdout.strip().split('\n')
            
            for pid in pids:
                if not pid.isdigit(): continue
                try:
                    proc_name = subprocess.check_output(["ps", "-p", pid, "-o", "comm="], text=True).strip()
                    if proc_name == "mysqld":
                        try:
                            real_path = os.readlink(f"/proc/{pid}/exe")
                            print(f"\n    -> Found PID {pid}")
                            print(f"    -> Binary: {real_path}")
                            return pid
                        except OSError:
                            pass 
                except subprocess.CalledProcessError:
                    continue 
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        
        time.sleep(0.5)
        print(".", end="", flush=True)

    raise RuntimeError(f"Failed to retrieve MySQL server PID. No process named 'mysqld' found using path: {unique_data_path}")


def run_helper_script(build_dir, task_name, args_list=None, capture=True, timeout=300, client_core="2"):
    """Helper to run a task, optionally pinning it to a core."""
    if args_list is None: args_list = []
    command = ["taskset", "-c", client_core, "./run-benchmark.sh", build_dir, task_name] + args_list
    
    try:
        result = subprocess.run(command, check=True, capture_output=capture, text=True, timeout=timeout)
        return result
    except subprocess.CalledProcessError as e:
        print(f"\n❌ ERROR: Failed to run '{task_name}' for {build_dir}")
        print(e.stdout)
        print(e.stderr)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"\n❌ ERROR: Timeout during '{task_name}' for {build_dir}")
        sys.exit(1)


def setup_databases_once():
    print("="*80)
    print("🚀 Starting One-Time Database Setup (mysqld --initialize-insecure)")
    
    for name, config in TARGETS.items():
        build_dir = config["build_dir"]
        print(f"--- Initializing DB for [{name}] in {build_dir}")
        
        data_dir = os.path.join(build_dir, "bench.dir", "data.dir")
        if os.path.exists(os.path.join(data_dir, "mysql")):
             print(f"ℹ️ Database directory already exists. Skipping 'setup_db'.")
        else:
             run_helper_script(build_dir, "setup_db")
             print(f"✅ DB for [{name}] initialized successfully.")
            
    print("✅ All databases initialized successfully.\n" + "="*80 + "\n")


def run_benchmark():
    setup_databases_once()

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    base_results_dir = f"{BASE_DIR}mysql_results_{timestamp}"
    os.makedirs(base_results_dir, exist_ok=True)
    print(f"📂 Saving all results to: {base_results_dir}\n")
    
    if os.path.exists(JSON_SRC_FILE):
        shutil.copy(JSON_SRC_FILE, base_results_dir)

    benchmark_dirs = {}
    for name in TARGETS.keys():
        sanitized_name = name.replace(" ", "_")
        benchmark_dir = os.path.join(base_results_dir, sanitized_name)
        os.makedirs(benchmark_dir, exist_ok=True)
        benchmark_dirs[name] = benchmark_dir

    print("\n" + "="*80)
    print("🚀 Starting Formal Benchmark Runs (Batched)")
    
    for name, config in TARGETS.items():
        print(f"🚀 Starting Batch for [{name}] ({NUM_RUNS} runs)")
        build_dir = config["build_dir"]
        results_dir = benchmark_dirs[name]
        
        for i in range(1, NUM_RUNS + 1):
            output_file = os.path.join(results_dir, f"run_{i}.txt")
            run_log_stdout = ""
            
            try:
                # --- 1. START SERVER ---
                print(f"--- Running [{name}] Iteration {i} of {NUM_RUNS}... (Starting server...)", end="", flush=True)
                run_helper_script(build_dir, "start_server") 
                server_pid = get_mysqld_pid(build_dir)
                
                # --- 2. CREATE DATABASE ---
                print(f" (Creating DB...)", end="", flush=True)
                run_helper_script(build_dir, "create_database")

                # --- 3. RUN WORKLOAD ---
                for test in SYSBENCH_WORKLOAD:
                    test_name = test['name']
                    client_core = test.get('client_core', '2') 
                    
                    print(f"\n    > {test_name}: (Prepare...)", end="", flush=True)
                    run_helper_script(build_dir, test["prepare_cmd"][0], test["prepare_cmd"][1:], client_core=client_core)

                    print(" (Run...)", end="", flush=True)
                    run_command_list = ["taskset", "-c", client_core, "./run-benchmark.sh", build_dir] + test["run_cmd"]
                    
                    # --- RUN SYSBENCH (NO PERF) ---
                    sysbench_result = subprocess.run(
                        run_command_list,
                        check=True, 
                        capture_output=True, 
                        text=True, 
                        timeout=600
                    )
                    
                    run_log_stdout += f"\n--- Output for {test_name} ---\n{sysbench_result.stdout.strip()}\n"

                    print(" (Cleanup...)", end="", flush=True)
                    run_helper_script(build_dir, test["cleanup_cmd"][0], test["cleanup_cmd"][1:], client_core=client_core)

                # --- 4. STOP SERVER ---
                print("\n    > (Stopping server...)", end="", flush=True)
                run_helper_script(build_dir, "stop_server")

                with open(output_file, 'w') as f:
                    f.write(f"Results for Benchmark: {name} - Run {i}\n")
                    f.write("="*40 + "\n\n")
                    f.write("--- Script Output (stdout) ---\n")
                    f.write(run_log_stdout + "\n\n")

                print(f" ✅ Done. Results saved to: {output_file}")

            except RuntimeError as e:
                print(f"❌ Error during Benchmark: {e}")
                try: run_helper_script(build_dir, "stop_server")
                except: pass 
            except Exception as e:
                print(f"❌ Error: {e}")
                try: run_helper_script(build_dir, "stop_server")
                except: pass 
        
        print(f"--- Batch for [{name}] complete ---")
        print("-" * 80)

    print("\n\n🎉 All benchmark runs complete.")

if __name__ == "__main__":
    run_benchmark()