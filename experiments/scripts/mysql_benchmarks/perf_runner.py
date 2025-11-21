import subprocess
import sys
import os
import datetime
import shutil
import signal
import time
from collections import defaultdict

# --- Configuration ---
NUM_RUNS = 10
TARGETS = {
    "PreserveNone_MySQL": {
        "build_dir": "../../../../ipra-run/mysql_benchmark/pn_thinlto_autofdo_mysql",
    },
    "Baseline_MySQL": {
        "build_dir": "../../../../ipra-run/mysql_benchmark/thinlto_autofdo_mysql"
    }
}

# --- This is the workload definition with CPU Pinning ---
SYSBENCH_WORKLOAD = [
    {
        "name": "oltp_read_write",
        "prepare_cmd": ["prepare_oltp_read_write"],
        "run_cmd": ["run_oltp_read_write", "1"],
        "cleanup_cmd": ["cleanup_oltp_read_write"],
        "client_core": "2" 
    },
    {
        "name": "oltp_update_index",
        "prepare_cmd": ["prepare_oltp_update_index"],
        "run_cmd": ["run_oltp_update_index", "1"],
        "cleanup_cmd": ["cleanup_oltp_update_index"],
        "client_core": "2"
    },
    {
        "name": "oltp_delete",
        "prepare_cmd": ["prepare_oltp_delete"],
        "run_cmd": ["run_oltp_delete", "1"],
        "cleanup_cmd": ["cleanup_oltp_delete"],
        "client_core": "2"
    },
    {
        "name": "select_random_ranges",
        "prepare_cmd": ["prepare_select_random_ranges"],
        "run_cmd": ["run_select_random_ranges", "1"],
        "cleanup_cmd": ["cleanup_select_random_ranges"],
        "client_core": "2"
    },
    {
        "name": "oltp_read_only",
        "prepare_cmd": ["prepare_oltp_read_only"],
        "run_cmd": ["run_oltp_read_only", "1"],
        "cleanup_cmd": ["cleanup_oltp_read_only"],
        "client_core": "2"
    }
]

# Copy json prof_data for documentation
JSON_SRC_FILE = '../../metrics/pn_functions/thinlto_autofdo_mysql_pn_functions/liveness_profdata.json'
BASE_DIR = f"../../metrics/references/mysql_results/"
PERF_EVENTS = "instructions,cycles,L1-icache-load-misses,iTLB-load-misses"
# ---------------------

def get_mysqld_pid(build_dir):
    """
    Finds the PID of the ACTUAL mysqld binary and VERIFIES the path.
    """
    unique_data_path = os.path.join(build_dir, "bench.dir", "data.dir")
    
    MAX_WAIT_SECONDS = 30 
    print(" (Searching OS for mysqld PID)", end="", flush=True)

    for attempt in range(int(MAX_WAIT_SECONDS / 0.5)):
        try:
            # Use 'pgrep -f' to search based on the unique data path argument
            pgrep_command = ["pgrep", "-f", f"mysqld.*{os.path.basename(unique_data_path)}"]
            result = subprocess.run(
                pgrep_command,
                capture_output=True,
                text=True,
                check=True,
                timeout=5
            )
            
            pids = result.stdout.strip().split('\n')
            
            for pid in pids:
                if not pid.isdigit(): continue
                
                try:
                    # 1. Verify Process Name is 'mysqld' (not sh or mysqld_safe)
                    proc_name = subprocess.check_output(["ps", "-p", pid, "-o", "comm="], text=True).strip()
                    
                    if proc_name == "mysqld":
                        # 2. CRITICAL CHECK: Verify the Binary Path on disk
                        try:
                            real_path = os.readlink(f"/proc/{pid}/exe")
                            print(f"\n     -> Found PID {pid}")
                            print(f"     -> Binary: {real_path}")
                            
                            abs_build_dir = os.path.abspath(build_dir)
                            if os.path.commonpath([abs_build_dir, real_path]) != abs_build_dir:
                                print(f"     ⚠️ WARNING: Running binary {real_path} seems outside build dir {abs_build_dir}")
                            
                            return pid
                        except OSError:
                            pass # Permission denied or process died
                            
                except subprocess.CalledProcessError:
                    continue 

        except subprocess.CalledProcessError:
            pass 
        except subprocess.TimeoutExpired:
             pass
        
        time.sleep(0.5)
        print(".", end="", flush=True)

    raise RuntimeError(f"Failed to retrieve MySQL server PID. No process named 'mysqld' found using path: {unique_data_path}")


def run_helper_script(build_dir, task_name, args_list=None, capture=True, timeout=300, client_core="2"):
    """Helper to run a task, optionally pinning it to a core."""
    if args_list is None:
        args_list = []
    
    command = ["taskset", "-c", client_core, "./run-benchmark.sh", build_dir, task_name] + args_list
    
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
    print("="*80)
    print("🚀 Starting One-Time Database Setup (mysqld --initialize-insecure)")
    print("This may take a minute...")
    
    for name, config in TARGETS.items():
        build_dir = config["build_dir"]
        print(f"--- Initializing DB for [{name}] in {build_dir}")
        
        data_dir = os.path.join(build_dir, "bench.dir", "data.dir")
        if os.path.exists(os.path.join(data_dir, "mysql")):
             print(f"ℹ️ Database directory already exists. Skipping 'setup_db'.")
        else:
             # This runs setup_db to initialize the data files.
             run_helper_script(build_dir, "setup_db")
             print(f"✅ DB for [{name}] initialized successfully.")
            
    print("✅ All databases initialized successfully.")
    print("="*80 + "\n")


def run_benchmark():
    # --- Run one-time setup first ---
    setup_databases_once()

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    base_results_dir = f"{BASE_DIR}mysql_results_{timestamp}"
    os.makedirs(base_results_dir, exist_ok=True)
    print(f"📂 Saving all results to: {base_results_dir}\n")
    
    if os.path.exists(JSON_SRC_FILE):
        print('📂 For record, documenting liveness_profdata.json...')
        shutil.copy(JSON_SRC_FILE, base_results_dir)

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
    
    for name, config in TARGETS.items():
        print(f"🚀 Starting Batch for [{name}] ({NUM_RUNS} runs)")
    
        build_dir = config["build_dir"]
        results_dir = benchmark_dirs[name]
        
        for i in range(1, NUM_RUNS + 1):
            output_file = os.path.join(results_dir, f"run_{i}.txt")
            run_log_stdout = ""
            run_log_stderr = ""
            server_pid = None
            
            try:
                # --- 1. START SERVER ---
                print(f"--- Running [{name}] Iteration {i} of {NUM_RUNS}... (Starting server...)", end="", flush=True)
                run_helper_script(build_dir, "start_server") 
                
                # This will now print the binary path for verification!
                server_pid = get_mysqld_pid(build_dir)
                
                # --- 2. CREATE DATABASE (Moved to the correct place for each run) ---
                print(f" (PID: {server_pid}) (Creating fresh DB...)", end="", flush=True)
                # This command will execute the create_database shell function
                run_helper_script(build_dir, "create_database")

                # --- 3. RUN WORKLOAD ---
                for test in SYSBENCH_WORKLOAD:
                    test_name = test['name']
                    client_core = test.get('client_core', '2') 
                    
                    print(f"\n    > {test_name}: (Prepare...)", end="", flush=True)
                    # Prepare command uses the full, descriptive name now (e.g., prepare_oltp_read_write)
                    run_helper_script(build_dir, test["prepare_cmd"][0], test["prepare_cmd"][1:], client_core=client_core)

                    print(" (Run & Profile...)", end="", flush=True)
                    
                    run_command_list = ["taskset", "-c", client_core, "./run-benchmark.sh", build_dir] + test["run_cmd"]
                    
                    perf_output_path = os.path.join(results_dir, f"temp_perf_{test_name}_{i}.txt")
                    perf_output_file = open(perf_output_path, "w")
                    
                    perf_command = ["perf", "stat", "-e", PERF_EVENTS, "-p", server_pid]
                    perf_process = subprocess.Popen(
                        perf_command,
                        stderr=perf_output_file, 
                        stdout=subprocess.DEVNULL
                    )

                    sysbench_result = subprocess.run(
                        run_command_list,
                        check=True, 
                        capture_output=True, 
                        text=True, 
                        timeout=600
                    )
                    
                    perf_process.send_signal(signal.SIGINT)
                    try:
                        perf_process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        perf_process.kill()
                        perf_process.wait()

                    perf_output_file.close()
                    
                    with open(perf_output_path, "r") as f:
                        perf_log_content = f.read()
                    os.remove(perf_output_path) 
                    
                    run_log_stdout += f"\n--- Output for {test_name} ---\n{sysbench_result.stdout.strip()}\n"
                    run_log_stderr += f"\n--- Perf for {test_name} ---\n{perf_log_content.strip()}\n"

                    print(" (Cleanup...)", end="", flush=True)
                    # Cleanup command uses the full, descriptive name
                    run_helper_script(build_dir, test["cleanup_cmd"][0], test["cleanup_cmd"][1:], client_core=client_core)

                # --- 4. STOP SERVER ---
                print("\n    > (Stopping server...)", end="", flush=True)
                run_helper_script(build_dir, "stop_server")

                with open(output_file, 'w') as f:
                    f.write(f"Results for Benchmark: {name} - Run {i}\n")
                    f.write("="*40 + "\n\n")
                    f.write("--- Script Output (stdout) ---\n")
                    f.write(f"--- Server PID: {server_pid} ---\n") # Added PID for easier tracing
                    f.write(run_log_stdout + "\n\n")
                    f.write("--- Perf Report (stderr) ---\n")
                    f.write(run_log_stderr + "\n")

                print(f" ✅ Done. Results saved to: {output_file}")

            except RuntimeError as e:
                print(f"❌ Error during Benchmark: {e}")
                print("Attempting to stop server...")
                try: run_helper_script(build_dir, "stop_server")
                except: pass 
            except Exception as e:
                print(f"❌ Error: {e}")
                try: run_helper_script(build_dir, "stop_server")
                except: pass
        
        print(f"--- Batch for [{name}] complete ---")
        print("-" * 80)

    print("\n\n🎉 All benchmark runs complete.")
    print(f"\n✅ Analyze the results with:")
    print(f"python3 perf_analyzer.py {base_results_dir}")

if __name__ == "__main__":
    run_benchmark()