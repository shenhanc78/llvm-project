#!/usr/bin/env python3
"""
Self-contained Python script for benchmarking MySQL builds with sysbench
and profiling the mysqld server with 'perf stat'.

This script ports all logic from the original:
- perf_runner.py
- run-benchmark.sh
- mysql-run-funcs.sh
"""

import subprocess
import sys
import os
import datetime
import shutil
import time
import signal
from pathlib import Path

# --- Configuration ---
NUM_RUNS = 10
BASE_BENCHMARK_DIR = "../../../../ipra-run/mysql_benchmark"

# 1. --- Updated TARGETS dictionary ---
TARGETS = {
    "Baseline_MySQL": {
        "build_dir": f"{BASE_BENCHMARK_DIR}/baseline_mysql",
    },
    "ThinLTO_MySQL": {
        "build_dir": f"{BASE_BENCHMARK_DIR}/thinlto_mysql",
    },
    "ThinLTO_AutoFDO_MySQL": {
        "build_dir": f"{BASE_BENCHMARK_DIR}/thinlto_autofdo_mysql",
    },
    "PN_ThinLTO_AutoFDO_MySQL": {
        "build_dir": f"{BASE_BENCHMARK_DIR}/pn_thinlto_autofdo_mysql",
    }
}

# --- This is the workload definition ---
SYSBENCH_WORKLOAD = [
    {
        "name": "oltp_read_write",
        "prepare": "prepare_oltp_rw",
        "run": "run_oltp_rw",
        "cleanup": "cleanup_oltp_rw"
    },
    {
        "name": "oltp_update_index",
        "prepare": "prepare_oltp_ui",
        "run": "run_oltp_ui",
        "cleanup": "cleanup_oltp_ui"
    },
    {
        "name": "oltp_delete",
        "prepare": "prepare_oltp_del",
        "run": "run_oltp_del",
        "cleanup": "cleanup_oltp_del"
    },
    {
        "name": "select_random_ranges",
        "prepare": "prepare_select_rr",
        "run": "run_select_rr",
        "cleanup": "cleanup_select_rr"
    },
    {
        "name": "oltp_read_only",
        "prepare": "prepare_oltp_ro",
        "run": "run_oltp_ro",
        "cleanup": "cleanup_oltp_ro"
    }
]

# Copy json prof_data for documentation
JSON_SRC_FILE = '../../metrics/pn_functions/thinlto_autofdo_mysql_pn_functions/liveness_profdata.json'
BASE_DIR = f"../../metrics/references/mysql_results/"

# 2. --- Improved PERF_EVENTS ---
PERF_EVENTS = "instructions,cycles,L1-icache-load-misses,L1-dcache-load-misses,L1-dcache-store-misses,iTLB-load-misses"
# ---------------------

class BenchmarkError(Exception):
    """Custom exception for benchmark failures."""
    pass

def run_command(cmd_list, cwd, capture=True, timeout=300, background=False, check=True):
    """General-purpose command running helper."""
    # Ensure all args are strings
    cmd_list = [str(arg) for arg in cmd_list]
    
    if background:
        return subprocess.Popen(cmd_list, cwd=cwd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
    try:
        result = subprocess.run(
            cmd_list,
            cwd=cwd,
            check=check,
            capture_output=capture,
            text=True,
            timeout=timeout
        )
        return result
            
    except subprocess.CalledProcessError as e:
        print(f"\n❌ ERROR: Command failed in {cwd}")
        print(f"  Command: {' '.join(e.args)}")
        if capture:
            print("\n--- STDOUT ---")
            print(e.stdout)
            print("\n--- STDERR ---")
            print(e.stderr)
        raise BenchmarkError(f"Command failed: {' '.join(e.args)}") from e
    except subprocess.TimeoutExpired as e:
        print(f"\n❌ ERROR: Timeout during command in {cwd}")
        print(f"  Command: {' '.join(e.args)}")
        raise BenchmarkError(f"Command timed out: {' '.join(e.args)}") from e


# === Ported functions from mysql-run-funcs.sh ===

def setup_mysql_config(bench_dir):
    """Writes the my.cnf file."""
    cnf_path = os.path.join(bench_dir, "install.dir", "my.cnf")
    socket_path = os.path.join(bench_dir, "mysqltest.sock")
    mysqlx_socket_path = os.path.join(bench_dir, "mysqlxtest.sock")
    
    my_cnf_content = f"""
[client]
local-infile = 1
loose-local-infile = 1
socket={socket_path}
mysqlx_socket={mysqlx_socket_path}

[server]
local-infile = 1

[mysqld]
local-infile = 1
secure_file_priv = ''
socket={socket_path}
mysqlx_socket={mysqlx_socket_path}
skip-networking
"""
    with open(cnf_path, 'w') as f:
        f.write(my_cnf_content)

def setup_db(bench_dir, data_dir):
    """Runs mysqld --initialize-insecure."""
    print(" (Removing old data...)", end="", flush=True)
    shutil.rmtree(data_dir, ignore_errors=True)
    os.makedirs(data_dir)
    
    print(" (Writing my.cnf...)", end="", flush=True)
    setup_mysql_config(bench_dir)
    
    print(" (Initializing DB...)", end="", flush=True)
    mysqld_path = os.path.join(bench_dir, "install.dir", "bin", "mysqld")
    cmd = [
        mysqld_path,
        f"--defaults-file={os.path.join(bench_dir, 'install.dir', 'my.cnf')}",
        f"--datadir={data_dir}",
        "--initialize-insecure",
        f"--user={os.getlogin()}"
    ]
    run_command(cmd, cwd=bench_dir, timeout=600)
    print(" Done.", flush=True)

def start_server(bench_dir, data_dir):
    """Starts mysqld_safe in the background."""
    setup_mysql_config(bench_dir)
    
    mysqld_safe_path = os.path.join(bench_dir, "install.dir", "bin", "mysqld_safe")
    cmd = [
        mysqld_safe_path,
        f"--defaults-file={os.path.join(bench_dir, 'install.dir', 'my.cnf')}",
        "--mysqld=mysqld",
        f"--datadir={data_dir}",
        "--skip-mysqlx",
        f"--pid-file={os.path.join(data_dir, 'mysqld.pid')}",
        f"--user={os.getlogin()}"
    ]
    
    run_command(cmd, cwd=bench_dir, background=True)
    time.sleep(8) # Wait for server to come up

def stop_server(bench_dir, data_dir):
    """Stops the mysqld server using the PID file."""
    pid_file = os.path.join(data_dir, "mysqld.pid")
    try:
        with open(pid_file, 'r') as f:
            pid = int(f.read().strip())
        
        os.kill(pid, signal.SIGTERM)
        time.sleep(3)
    except (IOError, FileNotFoundError, ValueError, ProcessLookupError) as e:
        print(f"\n  > Warning: Could not stop server via PID file ({e}). Trying pkill.")
        try:
            subprocess.run(["pkill", "mysqld"], check=False)
            time.sleep(3)
        except Exception as pkill_e:
            print(f"\n  > Warning: pkill failed: {pkill_e}")

def create_database(bench_dir):
    """Creates the 'sysbench' database."""
    mysql_path = os.path.join(bench_dir, "install.dir", "bin", "mysql")
    socket_path = os.path.join(bench_dir, "mysqltest.sock")
    cmd = [
        mysql_path,
        "-u", "root",
        f"--socket={socket_path}",
        "-e", "DROP DATABASE IF EXISTS sysbench; CREATE DATABASE sysbench;"
    ]
    run_command(cmd, cwd=bench_dir)

def _get_sysbench_base_cmd(bench_dir):
    socket_path = os.path.join(bench_dir, "mysqltest.sock")
    return [
        "sysbench",
        "--table-size=10000",
        "--num-threads=1",
        "--rand-type=uniform",
        "--rand-seed=1",
        "--db-driver=mysql",
        "--mysql-db=sysbench",
        "--tables=1",
        f"--mysql-socket={socket_path}",
        "--mysql-user=root"
    ]

# --- OLTP Read/Write ---
def prepare_oltp_rw(bench_dir):
    cmd = _get_sysbench_base_cmd(bench_dir) + ["oltp_read_write", "prepare"]
    run_command(cmd, cwd=bench_dir)

def run_oltp_rw(bench_dir):
    cmd = _get_sysbench_base_cmd(bench_dir) + [
        "oltp_read_write",
        "--events=2500",
        "--range_selects=off",
        "--skip_trx",
        "run"
    ]
    return run_command(cmd, cwd=bench_dir) # Return result for parsing

def cleanup_oltp_rw(bench_dir):
    cmd = _get_sysbench_base_cmd(bench_dir) + ["oltp_read_write", "cleanup"]
    run_command(cmd, cwd=bench_dir)

# --- OLTP Update Index ---
def prepare_oltp_ui(bench_dir):
    cmd = _get_sysbench_base_cmd(bench_dir) + ["oltp_update_index", "prepare"]
    run_command(cmd, cwd=bench_dir)

def run_oltp_ui(bench_dir):
    cmd = _get_sysbench_base_cmd(bench_dir) + [
        "oltp_update_index",
        "--events=2500",
        "--range_selects=off",
        "--skip_trx",
        "run"
    ]
    return run_command(cmd, cwd=bench_dir)

def cleanup_oltp_ui(bench_dir):
    cmd = _get_sysbench_base_cmd(bench_dir) + ["oltp_update_index", "cleanup"]
    run_command(cmd, cwd=bench_dir)

# --- OLTP Delete ---
def prepare_oltp_del(bench_dir):
    cmd = _get_sysbench_base_cmd(bench_dir) + ["oltp_delete", "prepare"]
    run_command(cmd, cwd=bench_dir)

def run_oltp_del(bench_dir):
    cmd = _get_sysbench_base_cmd(bench_dir) + [
        "oltp_delete",
        "--events=2500",
        "--range_selects=off",
        "--skip_trx",
        "run"
    ]
    return run_command(cmd, cwd=bench_dir)

def cleanup_oltp_del(bench_dir):
    cmd = _get_sysbench_base_cmd(bench_dir) + ["oltp_delete", "cleanup"]
    run_command(cmd, cwd=bench_dir)

# --- Select Random Ranges ---
def prepare_select_rr(bench_dir):
    cmd = _get_sysbench_base_cmd(bench_dir) + ["select_random_ranges", "prepare"]
    run_command(cmd, cwd=bench_dir)

def run_select_rr(bench_dir):
    cmd = _get_sysbench_base_cmd(bench_dir) + [
        "select_random_ranges",
        "--events=2500",
        "--range_selects=off",
        "--skip_trx",
        "run"
    ]
    return run_command(cmd, cwd=bench_dir)

def cleanup_select_rr(bench_dir):
    cmd = _get_sysbench_base_cmd(bench_dir) + ["select_random_ranges", "cleanup"]
    run_command(cmd, cwd=bench_dir)

# --- OLTP Read Only ---
def prepare_oltp_ro(bench_dir):
    # Note: Different table size
    base_cmd = _get_sysbench_base_cmd(bench_dir)
    base_cmd[base_cmd.index("--table-size=10000")] = "--table-size=500000"
    
    run_command(base_cmd + ["oltp_read_only", "prepare"], cwd=bench_dir)
    run_command(base_cmd + ["oltp_read_only", "prewarm"], cwd=bench_dir)

def run_oltp_ro(bench_dir):
    base_cmd = _get_sysbench_base_cmd(bench_dir)
    base_cmd[base_cmd.index("--table-size=10000")] = "--table-size=500000"
    cmd = base_cmd + [
        "oltp_read_only",
        "--events=30000",
        "--range_selects=off",
        "--skip_trx",
        "run"
    ]
    return run_command(cmd, cwd=bench_dir)

def cleanup_oltp_ro(bench_dir):
    base_cmd = _get_sysbench_base_cmd(bench_dir)
    base_cmd[base_cmd.index("--table-size=10000")] = "--table-size=500000"
    cmd = base_cmd + ["oltp_read_only", "cleanup"]
    run_command(cmd, cwd=bench_dir)

# --- Function mapping ---
WORKLOAD_FUNCS = {
    "prepare_oltp_rw": prepare_oltp_rw, "run_oltp_rw": run_oltp_rw, "cleanup_oltp_rw": cleanup_oltp_rw,
    "prepare_oltp_ui": prepare_oltp_ui, "run_oltp_ui": run_oltp_ui, "cleanup_oltp_ui": cleanup_oltp_ui,
    "prepare_oltp_del": prepare_oltp_del, "run_oltp_del": run_oltp_del, "cleanup_oltp_del": cleanup_oltp_del,
    "prepare_select_rr": prepare_select_rr, "run_select_rr": run_select_rr, "cleanup_select_rr": cleanup_select_rr,
    "prepare_oltp_ro": prepare_oltp_ro, "run_oltp_ro": run_oltp_ro, "cleanup_oltp_ro": cleanup_oltp_ro,
}

# === End of ported functions ===


def get_mysqld_pid(data_dir, retries=10, delay=1):
    """Waits for and reads the mysqld.pid file."""
    pid_file = os.path.join(data_dir, "mysqld.pid")
    for i in range(retries):
        if os.path.exists(pid_file):
            try:
                with open(pid_file, 'r') as f:
                    pid_str = f.read().strip()
                    if pid_str and pid_str.isdigit():
                        # Verify the process is running
                        pid = int(pid_str)
                        os.kill(pid, 0) # Throws ProcessLookupError if not running
                        return str(pid)
            except (IOError, ValueError, ProcessLookupError) as e:
                print(f"  > Warning: Stale/invalid pid file (attempt {i+1}): {e}")
        
        if i < retries - 1:
            time.sleep(delay)
    
    # Fallback to pgrep if pid file fails
    print("  > PID file not found or stale. Trying pgrep mysqld...")
    try:
        result = subprocess.run(["pgrep", "-n", "mysqld"], capture_output=True, text=True, check=True)
        pid_str = result.stdout.strip()
        if pid_str and pid_str.isdigit():
            return pid_str
    except Exception as e:
        print(f"  > pgrep failed: {e}")
        
    return None


def setup_databases_once():
    """
    Runs the one-time database initialization for each target.
    """
    print("="*80)
    print("🚀 Starting One-Time Database Setup (mysqld --initialize-insecure)")
    print("This may take a minute...")
    
    for name, config in TARGETS.items():
        try:
            build_dir = str(Path(config["build_dir"]).resolve())
            bench_dir = os.path.join(build_dir, "bench.dir")
            data_dir = os.path.join(bench_dir, "data.dir")
            install_dir = os.path.join(build_dir, "install")
            
            os.makedirs(bench_dir, exist_ok=True)

            # Symlink install.dir (from run-benchmark.sh)
            link_path = os.path.join(bench_dir, "install.dir")
            if os.path.lexists(link_path):
                os.remove(link_path)
            os.symlink(install_dir, link_path)
            
            print(f"--- Initializing DB for [{name}] in {build_dir}")
            if os.path.exists(data_dir) and len(os.listdir(data_dir)) > 0:
                print(f"ℹ️ Database directory already exists. Skipping 'setup_db'.")
            else:
                setup_db(bench_dir, data_dir)
                print(f"✅ DB for [{name}] initialized successfully.")
                
        except Exception as e:
            print(f"❌ FAILED to initialize DB for [{name}]: {e}. Exiting.")
            sys.exit(1)
                
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
    
    for name, config in TARGETS.items():
        print(f"🚀 Starting Batch for [{name}] ({NUM_RUNS} runs)")
        
        build_dir = str(Path(config["build_dir"]).resolve())
        results_dir = benchmark_dirs[name]
        bench_dir = os.path.join(build_dir, "bench.dir")
        data_dir = os.path.join(bench_dir, "data.dir")
        
        for i in range(1, NUM_RUNS + 1):
            
            output_file = os.path.join(results_dir, f"run_{i}.txt")
            run_log_stdout = ""
            run_log_stderr = ""
            pid = None
            
            try:
                # --- 1. START SERVER (un-timed) ---
                print(f"--- Running [{name}] Iteration {i} of {NUM_RUNS}... (Starting server...)", end="", flush=True)
                start_server(bench_dir, data_dir)

                pid = get_mysqld_pid(data_dir)
                if not pid:
                    raise BenchmarkError(f"Could not find mysqld.pid for {name}")

                print(f" (PID: {pid}) (Creating DB...)", end="", flush=True)
                
                # --- 2. CREATE DATABASE (un-timed) ---
                create_database(bench_dir)

                # --- 3. RUN WORKLOAD (The core timed loop) ---
                for test in SYSBENCH_WORKLOAD:
                    test_name = test['name']
                    print(f"\n    > {test_name}: (Prepare...)", end="", flush=True)
                    
                    # 3a. PREPARE (un-timed)
                    WORKLOAD_FUNCS[test['prepare']](bench_dir)

                    # 3b. RUN (timed)
                    print(" (Run w/ Perf...)", end="", flush=True)
                    
                    # --- START PERF ---
                    perf_command = ["perf", "stat", "-p", pid, "-e", PERF_EVENTS]
                    perf_process = subprocess.Popen(perf_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

                    # --- RUN SYSBENCH ---
                    run_result = WORKLOAD_FUNCS[test['run']](bench_dir)
                    
                    # --- STOP PERF ---
                    perf_process.send_signal(signal.SIGINT)
                    try:
                        perf_stdout, perf_stderr = perf_process.communicate(timeout=60)
                    except subprocess.TimeoutExpired:
                        perf_process.kill()
                        perf_stdout, perf_stderr = perf_process.communicate()
                        perf_stderr += "\n\n--- PERF TIMEOUT ---"

                    # Store stdout (sysbench log) and stderr (perf log)
                    run_log_stdout += f"\n--- Output for {test_name} ---\n{run_result.stdout.strip()}\n"
                    run_log_stderr += f"\n--- Perf for {test_name} ---\n{perf_stderr.strip()}\n"

                    # 3c. CLEANUP (un-timed)
                    print(" (Cleanup...)", end="", flush=True)
                    WORKLOAD_FUNCS[test['cleanup']](bench_dir)

                # --- 4. STOP SERVER (un-timed) ---
                print("\n    > (Stopping server...)", end="", flush=True)
                stop_server(bench_dir, data_dir)
                pid = None # Server is stopped

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
            except Exception as e:
                print(f"\n❌ Error: Benchmark run {i} for {name} failed: {e}")
                with open(output_file, 'w') as f:
                    f.write(f"### ERROR during Benchmark: {name} - Run {i} ###\n\n")
                    f.write(f"Error: {e}\n\n")
                    if run_log_stdout: f.write("--- Stdout (Partial) ---\n" + run_log_stdout + "\n\n")
                    if run_log_stderr: f.write("--- Stderr (Partial) ---\n" + run_log_stderr + "\n")
                
                print(f"🔥 Error details saved to: {output_file}")

            finally:
                # --- Cleanup: Ensure server is stopped ---
                if pid:
                    print("\n    > (Cleanup: Stopping server after error...)", end="", flush=True)
                    try: 
                        stop_server(bench_dir, data_dir)
                        print(" Stopped.")
                    except Exception as stop_e:
                        print(f" Failed to stop server: {stop_e}")
            
        print(f"--- Batch for [{name}] complete ---")
        print("-" * 80) # Add a separator between batches

    print("\n\n🎉 All benchmark runs complete.")
    print(f"\n✅ Analyze the results with:")
    print(f"python3 perf_analyzer.py {base_results_dir}")


if __name__ == "__main__":
    # Ensure script is run from its own directory
    os.chdir(Path(__file__).parent.resolve())
    
    # Check for 'perf'
    if shutil.which("perf") is None:
        print("❌ Error: 'perf' command not found in PATH.", file=sys.stderr)
        print("Please install it (e.g., 'sudo apt install linux-tools-common linux-tools-generic').", file=sys.stderr)
        sys.exit(1)
        
    # Check for 'sysbench'
    if shutil.which("sysbench") is None:
        print("❌ Error: 'sysbench' command not found in PATH.", file=sys.stderr)
        print("Please install it (e.g., 'sudo apt install sysbench').", file=sys.stderr)
        sys.exit(1)

    run_benchmark()