# File: perf_pipeline.py
#
# Description:
#   A multi-stage pipeline for performance analysis.
#
# Usage:
#   Run Stage 1 (Benchmark & Profile):
#   $ python perf_pipeline.py 1
#
#   Run Stage 2 (Analyze Reports):
#   $ python perf_pipeline.py 2 <path_to_results_directory>
#
#   Run Stage 3 (Extract Artifacts):
#   $ python perf_pipeline.py 3 <path_to_results_directory>
#

import sys
import os
import re
import json
import hashlib
import subprocess
import datetime
from pathlib import Path

# --- ⚙️ CONFIGURATION (Required for all stages) ---
DEV_DIR = "/usr/local/google/home/tanjihui/ipra-run"
LLVM_SRC_DIR = "/usr/local/google/home/tanjihui/llvm-project"
BASELINE_BUILD_DIR = f"{DEV_DIR}/thinly_linked_fdo_clang"

COMMANDS = {
    "ThinLTO_FDO": {
        "run": [
            "/usr/local/google/home/tanjihui/Desktop/clangbench/do-clangbench.sh", "run_local",
            "--cc", f"{DEV_DIR}/thinly_linked_fdo_clang/bin/clang++",
            "--iterations", "1"
        ],
        "executable": f"{BASELINE_BUILD_DIR}/bin/clang",
        "cc": f"{DEV_DIR}/thinly_linked_fdo_clang/bin/clang++"
    },
    "Preserve_None": {
        "run": [
            "/usr/local/google/home/tanjihui/Desktop/clangbench/do-clangbench.sh", "run_local",
            "--cc", f"{DEV_DIR}/preserve_none_thinly_linked_fdo_clang/bin/clang++",
            "--iterations", "1"
        ],
        "executable": f"{DEV_DIR}/preserve_none_thinly_linked_fdo_clang/bin/clang",
        "cc": f"{DEV_DIR}/preserve_none_thinly_linked_fdo_clang/bin/clang++"
    }
}

CXXFLAGS_FOR_ARTIFACTS = (
    f"-I{LLVM_SRC_DIR}/llvm/include "
    f"-I{BASELINE_BUILD_DIR}/include "
    f"-I{LLVM_SRC_DIR}/clang/include "
    f"-I{BASELINE_BUILD_DIR}/tools/clang/include"
)
# ---------------------

def run_command(command, log_file):
    """Helper to run a command and log its output."""
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=1800)
        with open(log_file, 'w') as f:
            f.write("--- STDOUT ---\n" + result.stdout + "\n--- STDERR ---\n" + result.stderr)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Error: Command failed. See log: {log_file}")
        with open(log_file, 'w') as f:
            f.write(f"### ERROR: {' '.join(command)} ###\n\n{e.stdout}\n{e.stderr}")
        return False
    except FileNotFoundError:
        print(f"❌ Error: Command not found: {command[0]}")
    except subprocess.TimeoutExpired:
        print(f"❌ Error: Command timed out. See log for details: {log_file}")
    return False

# ==============================================================================
# 📊 STAGE 1: Run Benchmarks and Collect Perf Data
# ==============================================================================
def stage_1_run_benchmarks():
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    base_results_dir = Path(f"../metrics/references/perf_records/perf_records_{timestamp}")
    base_results_dir.mkdir(parents=True, exist_ok=True)
    
    print("="*80)
    print("📊 STAGE 1: Running Benchmarks and Collecting Perf Data")
    print(f"📂 Saving results to: {base_results_dir.resolve()}")
    print("="*80)
    
    for name, config in COMMANDS.items():
        print(f"\n🚀 Profiling: {name}")
        benchmark_dir = base_results_dir / name
        benchmark_dir.mkdir(exist_ok=True)
        
        perf_data_file = benchmark_dir / "perf.data"
        perf_report_file = benchmark_dir / "report.txt"
        log_file = benchmark_dir / "run.log"

        print(f"  -> Running perf record...", end="", flush=True)
        perf_command = ["perf", "record", "-e", "instructions:u", "-o", str(perf_data_file), "--"] + config["run"]
        if not run_command(perf_command, log_file): sys.exit(1)
        print(" ✅ Done.")

        print(f"  -> Generating perf report...", end="", flush=True)
        report_command = ["perf", "report", "--stdio", "-i", str(perf_data_file), "--no-demangle"]
        if not run_command(report_command, perf_report_file): sys.exit(1)
        print(f" ✅ Done.")
        
    print("\n\n🎉 Stage 1 complete.")
    print("You can now run Stage 2 with the following command:")
    print(f"   python {sys.argv[0]} 2 {base_results_dir.resolve()}")

# ==============================================================================
# 📈 STAGE 2: Analyze Perf Reports
# ==============================================================================
def stage_2_analyze_results(base_dir):
    print("="*80)
    print("📈 STAGE 2: Analyzing Perf Reports")
    print(f"📂 Reading from: {base_dir.resolve()}")
    print("="*80)

    def parse_perf_report(filename):
        data = {}
        pattern = re.compile(r"^\s*([0-9.]+)%\s+.*\s+\[\.\]\s+(.*)$")
        total_inst_count_pattern = re.compile(r"# Event count \(approx.\): (\d+)")
        total_inst_count = float('-inf')
        with open(filename, 'r') as f:
            for line in f:
                match = total_inst_count_pattern.match(line)
                if match:
                    total_inst_count = int(match.group(1))
                    continue

                match = pattern.match(line)
                if match:
                    func_name = match.group(2).strip().split('.')[0]
                    data[func_name] = float(match.group(1)) * total_inst_count
        return data

    baseline_data = parse_perf_report(base_dir / "ThinLTO_FDO" / "report.txt")
    preserve_none_data = parse_perf_report(base_dir / "Preserve_None" / "report.txt")
    
    deltas = {
        func: preserve_none_data.get(func) - baseline_data.get(func)
        for func in set(baseline_data.keys()) | set(preserve_none_data.keys())
        if func in preserve_none_data and func in baseline_data
    }
    sorted_funcs = sorted(deltas.items(), key=lambda item: item[1])
    
    best_funcs = [f[0] for f in sorted_funcs[:5]]
    worst_funcs = [f[0] for f in sorted_funcs[-5:][::-1]]

    print("\n--- ✅ Top 5 Best Functions (Instructions Decreased) ---")
    for func in best_funcs:
        print(f"{deltas[func]} : {func}")
    print("\n--- ❌ Top 5 Worst Functions (Instructions Increased) ---")
    for func in worst_funcs: print(f"{deltas[func]} : {func}")
        
    analysis_output_file = base_dir / "analysis.json"
    with open(analysis_output_file, 'w') as f:
        json.dump({"best": best_funcs, "worst": worst_funcs}, f, indent=4)
        
    print(f"\n\n🎉 Stage 2 complete. Analysis saved to: {analysis_output_file}")
    print("You can now run Stage 3 with the following command:")
    print(f"   python {sys.argv[0]} 3 {base_dir.resolve()}")

# ==============================================================================
# 🛠️ STAGE 3: Extract Artifacts
# ==============================================================================
# (Keep all your other functions and config the same)

def stage_3_extract_artifacts(base_dir):
    analysis_file = base_dir / "analysis.json"
    if not analysis_file.is_file():
        print(f"Error: analysis.json not found in '{base_dir}'. Please run Stage 2 first.")
        sys.exit(1)

    with open(analysis_file, 'r') as f:
        functions_to_process = json.load(f)

    print("="*80)
    print("🛠️ STAGE 3: Extracting Artifacts")
    print(f"📂 Reading from: {analysis_file}")
    print("="*80)
    
    for category, functions in functions_to_process.items():
        print(f"\n--- Processing '{category}' functions ---")
        for full_func_name in functions:
            base_func_name = re.sub(r"\s*\[clone \..*\]$", "", full_func_name).strip()
            print(f"\n🔍 Processing function: {full_func_name}")

            temp_name = base_func_name.replace("(anonymous namespace)", "").strip()
            temp_name = temp_name.split('<')[0].split('(')[0]
            core_func_name = temp_name.split("::")[-1] if "::" in temp_name else temp_name
            print(f"  -> Using core name for search: {core_func_name}")
            
            sanitized_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', base_func_name)
            if len(sanitized_name) > 100:
                hash_suffix = hashlib.md5(full_func_name.encode()).hexdigest()[:8]
                sanitized_name = f"{sanitized_name[:100]}_{hash_suffix}"
            artifact_dir = base_dir / "artifacts" / category / sanitized_name
            artifact_dir.mkdir(parents=True, exist_ok=True)

            executable = COMMANDS["ThinLTO_FDO"]["executable"]
            source_file = None
            try:
                # --- FINAL SOLUTION: Use 'info functions' for a robust regex search ---
                gdb_command = [
                    "gdb", "-batch", 
                    "-ex", f"directory {LLVM_SRC_DIR}",
                    # Search for any function matching the core name
                    "-ex", f"info functions {core_func_name}", 
                    executable
                ]
                result = subprocess.check_output(gdb_command, text=True, stderr=subprocess.DEVNULL)
                
                # --- New parsing logic for 'info functions' output ---
                found_files = []
                for line in result.splitlines():
                    if line.startswith("File "):
                        # GDB output is "File /path/to/file.cpp:"
                        filepath = line.split(' ')[1].strip()[:-1]
                        found_files.append(filepath)
                
                if not found_files:
                    print(f"  -> ⚠️ GDB search returned no files for '{core_func_name}'. Skipping."); continue
                
                # Heuristic: Prefer a .cpp file over a .h file if multiple are found
                source_files = [f for f in found_files if f.endswith(('.cpp', '.cc', '.c'))]
                if source_files:
                    source_file = Path(source_files[0])
                else:
                    source_file = Path(found_files[0]) # Fallback to first result

                if not source_file.is_absolute():
                    source_file = Path(LLVM_SRC_DIR) / source_file

                print(f"  -> Found source file: {source_file.resolve()}")

            except subprocess.CalledProcessError as e:
                print(f"  -> ⚠️ GDB command failed for '{core_func_name}'. Skipping."); continue
            
            # Generate artifacts
            for name, config in COMMANDS.items():
                print(f"  -> Generating artifacts for {name} version...")
                cc, flags = config["cc"], CXXFLAGS_FOR_ARTIFACTS.split()
                ir_file = artifact_dir / f"{name}.ll"
                cmd_ir = [cc, "-S", "-emit-llvm", str(source_file), "-o", str(ir_file)] + flags
                run_command(cmd_ir, artifact_dir / f"{name}_ir.log")
                asm_file = artifact_dir / f"{name}.s"
                cmd_asm = [cc, "-S", str(source_file), "-o", str(asm_file)] + flags
                run_command(cmd_asm, artifact_dir / f"{name}_asm.log")
            
            print(f"  -> ✅ Artifacts saved in: {artifact_dir}")
    
    print("\n\n🎉 Stage 3 complete.")

# ==============================================================================
# Main Dispatcher
# ==============================================================================
def print_usage():
    """Prints the help message."""
    print("Usage: python perf_pipeline.py <stage> [path]")
    print("\nStages:")
    print("  1          : Run benchmarks and create perf reports in a new timestamped directory.")
    print("  2 <path>   : Analyze reports from a specified directory and create analysis.json.")
    print("  3 <path>   : Extract IR/Assembly artifacts using the analysis.json in a directory.")
    print("\nExample:")
    print("  python perf_pipeline.py 1")
    print("  python perf_pipeline.py 2 references/perf_records/perf_records_...")
    print("  python perf_pipeline.py 3 references/perf_records/perf_records_...")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)

    stage = sys.argv[1]

    if stage == '1':
        if len(sys.argv) != 2:
            print("Error: Stage 1 does not take a path argument.\n")
            print_usage()
            sys.exit(1)
        stage_1_run_benchmarks()
    
    elif stage in ['2', '3']:
        if len(sys.argv) != 3:
            print(f"Error: Stage {stage} requires a path to a results directory.\n")
            print_usage()
            sys.exit(1)
        
        base_dir = Path(sys.argv[2])
        if not base_dir.is_dir():
            print(f"Error: Directory not found at '{base_dir}'")
            sys.exit(1)
            
        if stage == '2':
            stage_2_analyze_results(base_dir)
        elif stage == '3':
            stage_3_extract_artifacts(base_dir)
            
    else:
        print(f"Error: Invalid stage '{stage}'. Must be 1, 2, or 3.\n")
        print_usage()
        sys.exit(1)