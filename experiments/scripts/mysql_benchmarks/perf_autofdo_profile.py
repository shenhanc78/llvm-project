import subprocess
import sys
import os
import time
import signal
import datetime
import shutil

# --- Configuration ---
# PERF_EVENT_NAME must be 'BR_INST_RETIRED.NEAR_TAKEN' for AutoFDO.
PERF_EVENT_NAME = "BR_INST_RETIRED.NEAR_TAKEN"
# -b (branch stack) is mandatory for AutoFDO.
PERF_FLAGS = ["-b"]
PERF_FREQUENCY = "-c 500009" 

# --- Helper Functions ---

def log(message):
    """Simple logging helper."""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"\n--- {timestamp} ---")
    print(f"--- {message}")
    print("-----------------------------------------------------", flush=True)

def run_shell_command(command, check=True):
    """Wrapper for running external shell commands."""
    try:
        # Use shell=True for running scripts/commands. Output is directed to the terminal.
        subprocess.run(command, shell=True, check=check, 
                       stdout=sys.stdout, stderr=sys.stderr)
    except subprocess.CalledProcessError as e:
        print(f"\n❌ ERROR: Command failed with return code {e.returncode}")
        print(f"Command: {command}")
        sys.exit(1)

def get_mysqld_pid_robust(build_dir):
    """
    Robustly finds the PID of the actual mysqld process using unique path identification 
    and verifies the binary link, including a 30-second retry loop.
    """
    # Use the unique part of the build directory path for identification (e.g., 'autofdo_metadata_mysql')
    unique_dir_name = os.path.basename(build_dir)
    # The expected absolute path of the mysqld binary
    expected_bin_path = os.path.join(build_dir, "install", "bin", "mysqld")
    
    MYSQLD_PID = ""
    MAX_WAIT_SECONDS = 30
    MAX_ATTEMPTS = int(MAX_WAIT_SECONDS / 0.5) 
    
    print(" (Searching OS for mysqld PID)", end="", flush=True)

    for i in range(MAX_ATTEMPTS):
        # 1. Find PIDs associated with our unique directory name in the command line
        try:
            # We assume the unique directory name is visible in the mysqld command line args (e.g., --datadir)
            pgrep_cmd = f"pgrep -d ' ' -f 'mysqld.*{unique_dir_name}'"
            pids_result = subprocess.run(
                pgrep_cmd,
                shell=True,
                capture_output=True,
                text=True,
                check=False,
                timeout=5
            )
            PIDS = pids_result.stdout.strip().split()
        except subprocess.TimeoutExpired:
            PIDS = []
        
        for PID in PIDS:
            if not PID.isdigit(): continue
            
            try:
                # 2. Check Process Name is 'mysqld' (not the 'mysqld_safe' wrapper)
                proc_name = subprocess.check_output(f"ps -p {PID} -o comm=", shell=True, text=True).strip()
                # 3. CRITICAL CHECK: Verify the Binary Path (/proc/PID/exe)
                real_path = os.readlink(f"/proc/{PID}/exe")
                
                if proc_name == "mysqld" and real_path == expected_bin_path:
                    MYSQLD_PID = PID
                    print(f"\n   -> Found verified PID: {PID})", flush=True)
                    return MYSQLD_PID
            except (OSError, subprocess.CalledProcessError):
                continue

        time.sleep(0.5)
        if (i + 1) % 10 == 0:
            print(".", end="", flush=True)
            
    raise RuntimeError(f"Failed to retrieve verified MySQL server PID after {MAX_WAIT_SECONDS} seconds.")


def run_perf_profiling(build_dir, autofdo_perf_file):
    """Executes the full perf profiling run."""
    perf_process = None
    try:
        # --- 1. START SERVER (Uses run-benchmark.sh setup_and_start) ---
        log("Starting MySQL Server")
        run_shell_command(f"./run-benchmark.sh {build_dir} setup_and_start")
        
        # --- 2. GET PID (Robustly) ---
        MYSQLD_PID = get_mysqld_pid_robust(build_dir)
        
        # --- 3. START PERF RECORD (in background) ---
        log(f"Starting perf record on PID {MYSQLD_PID} (Event: {PERF_EVENT_NAME} {PERF_FLAGS} Rate: {PERF_FREQUENCY})")
        
        # Build the perf record command including the mandatory -b flag for AutoFDO
        perf_cmd_list = ["perf", "record", "-e", PERF_EVENT_NAME, *PERF_FLAGS, PERF_FREQUENCY, "-p", MYSQLD_PID, "-o", autofdo_perf_file]
        perf_command = " ".join(perf_cmd_list)
        
        # Start perf in the background using subprocess.Popen
        perf_process = subprocess.Popen(
            perf_command,
            shell=True,
            preexec_fn=os.setsid 
        )
        PERF_PID = perf_process.pid
        print(f"Perf process started with PID: {PERF_PID}")
        
        time.sleep(2) # Wait briefly for perf to start sampling
        
        # --- 4. RUN WORKLOAD (in foreground, uses run-benchmark.sh run_sysbench_loadtest) ---
        log("Running sysbench workload (Profiling active)")
        run_shell_command(f"./run-benchmark.sh {build_dir} run_sysbench_loadtest")

        # --- 5. STOP PERF RECORD (Graceful stop via SIGINT) ---
        log("Workload finished. Stopping perf record...")
        
        # Send SIGINT to the process group for graceful shutdown
        os.killpg(os.getpgid(PERF_PID), signal.SIGINT)
        
        try:
            perf_process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            print("⚠️ WARNING: Perf process took too long to stop. Sending SIGKILL.")
            perf_process.kill()
        
        # Check for clean exit (0 or SIGINT code)
        if perf_process.returncode != 0 and perf_process.returncode != -signal.SIGINT:
             print(f"❌ ERROR: Perf process exited with code {perf_process.returncode}")

    except Exception as e:
        print(f"\n❌ CRITICAL ERROR DURING PROFILING: {e}")
        # Clean up the background perf process if it's still running
        if perf_process and perf_process.poll() is None:
            os.killpg(os.getpgid(perf_process.pid), signal.SIGINT)
            perf_process.wait(timeout=5)
            
        # --- 6. STOP SERVER (Clean up the server regardless of error) ---
        log("Attempting to stop MySQL Server due to error.")
        run_shell_command(f"./run-benchmark.sh {build_dir} stop_server", check=False)
        sys.exit(1)

    finally:
        # --- 6. STOP SERVER (Final cleanup) ---
        log("Stopping MySQL Server")
        run_shell_command(f"./run-benchmark.sh {build_dir} stop_server")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 perf_autofdo_profile.py <build_dir> <output_perf_file>")
        sys.exit(1)
        
    build_dir = sys.argv[1]
    autofdo_perf_file = sys.argv[2]
    
    # Resolve relative paths to absolute paths for robust Popen/pgrep matching
    run_perf_profiling(os.path.abspath(build_dir), os.path.abspath(autofdo_perf_file))