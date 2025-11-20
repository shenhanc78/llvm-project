# --- Standard Library Imports ---
import os
import re
import sys
from collections import defaultdict

# --- Data Science & Stats Imports ---
import numpy as np
from scipy import stats
import pandas as pd

# --- Plotting Imports ---
import matplotlib.pyplot as plt
import seaborn as sns

# --- Configuration ---
# ⚠️ UPDATE THIS PATH TO YOUR ACTUAL RESULTS DIRECTORY ⚠️
RESULTS_DIR = "../../metrics/references/mysql_results/mysql_results_2025-11-19_21-04-10"

# --- Plotting Style ---
sns.set(style="whitegrid", palette="muted")
plt.rcParams.update({'figure.max_open_warning': 0})

# --- Task Names (Must match your shell script order) ---
TASK_NAMES = [
    'oltp_read_write',
    'oltp_update_index',
    'oltp_delete',
    'select_random_ranges',
    'oltp_read_only'
]

# ==============================================================================
# 1. PARSING LOGIC
# ==============================================================================

def get_perf_patterns():
    """Defines and returns the metric patterns specific to MySQL benchmark."""
    return {
        'instructions': re.compile(r'([\d,]+)\s+instructions'),
        'cycles': re.compile(r'([\d,]+)\s+cycles'),
        'itlb_load_misses': re.compile(r'([\d,]+)\s+iTLB-load-misses'),
        'l1_icache_load_misses': re.compile(r'([\d,]+)\s+L1-icache-load-misses'),
        'user_time_s': re.compile(r'(\d+\.\d+)\s+seconds user'),
        'sys_time_s' : re.compile(r'(\d+\.\d+)\s+seconds sys'),
        'wall_time_s': re.compile(r'(\d+\.\d+)\s+seconds time elapsed'),
    }

def process_single_perf_report(report_content, patterns):
    """Parses a single 'perf stat' report block."""
    metrics = defaultdict(float)
    for key, pattern in patterns.items():
        match = pattern.search(report_content)
        if match:
            try:
                val = float(match.group(1).replace(',', ''))
                metrics[key] = val
            except (ValueError, IndexError):
                pass

    # Derived Metrics
    if metrics.get('cycles', 0) > 0:
        metrics['ipc'] = metrics.get('instructions', 0) / metrics['cycles']
    
    if 'sys_time_s' in metrics and 'user_time_s' in metrics:
        metrics['server_cpu_time_s'] = metrics['sys_time_s'] + metrics['user_time_s']
    
    # Remove raw time components to keep plots clean
    metrics.pop('user_time_s', None)
    metrics.pop('sys_time_s', None)
    
    if any(k in metrics for k in ['instructions', 'cycles', 'server_cpu_time_s']):
        return dict(metrics)
    return None

def parse_perf_data(stderr_content):
    """Parses stderr containing multiple perf reports."""
    patterns = get_perf_patterns()
    perf_reports = re.split(r'--- Perf for', stderr_content)
    parsed_reports = []
    
    # Skip header text before first split
    for report in perf_reports[1:]: 
        if any(char.isdigit() for char in report):
            metrics = process_single_perf_report(report, patterns)
            if metrics:
                parsed_reports.append(metrics)
    
    return parsed_reports

def parse_sysbench_logs(stdout_content):
    """Parses stdout for Sysbench TPS."""
    try:
        tps_matches = re.findall(r'transactions:\s+.*\((.*) per sec\.\)', stdout_content)
        tps_values = [float(tps) for tps in tps_matches]
        # Return list of TPS values (one per task)
        return [{'sysbench_tps': tps} for tps in tps_values]
    except Exception:
        return []

def analyze_directory(results_dir):
    """
    Walks directory and parses all run_*.txt files.
    Returns: all_data[bench_type][key][metric] = [list_of_values]
    Key can be an int (task index) or string 'Aggregated'
    """
    # Nested Dictionary: BenchName -> Key -> MetricName -> ListOfValues
    all_data = defaultdict(lambda: defaultdict(lambda: defaultdict(list))) 
    
    if not os.path.exists(results_dir):
        print(f"❌ Error: Directory not found at {results_dir}")
        return None

    benchmark_types = [d for d in os.listdir(results_dir) if os.path.isdir(os.path.join(results_dir, d))]
    
    for bench_type in benchmark_types:
        bench_path = os.path.join(results_dir, bench_type)
        run_files = sorted([f for f in os.listdir(bench_path) if f.startswith('run_') and f.endswith('.txt')])
        
        print(f"📁 Processing '{bench_type}' ({len(run_files)} runs)...")

        for run_file in run_files:
            file_path = os.path.join(bench_path, run_file)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except Exception as e:
                print(f"  [!] Could not read {run_file}: {e}")
                continue

            # Split Log
            stdout_match = re.search(r'--- Script Output \(stdout\) ---\n(.*?)\n\n--- Perf Report \(stderr\)', content, re.DOTALL)
            stderr_match = re.search(r'--- Perf Report \(stderr\) ---\n(.*)', content, re.DOTALL)

            if not stdout_match or not stderr_match:
                continue
            
            # Parse
            perf_results = parse_perf_data(stderr_match.group(1))
            sys_results = parse_sysbench_logs(stdout_match.group(1))
            
            # Align Tasks
            num_tasks = min(len(perf_results), len(sys_results))
            
            # --- Aggregation Container for THIS run ---
            run_agg = defaultdict(float)
            has_valid_tasks = False

            for i in range(num_tasks):
                # Merge Perf metrics + Sysbench metrics for this task index
                combined = {**perf_results[i], **sys_results[i]}
                
                # Store Task Data
                for metric, value in combined.items():
                    all_data[bench_type][i][metric].append(value)
                    
                    # Accumulate for Aggregation
                    # Note: IPC cannot be summed. We sum raw counts and recalculate IPC later.
                    if not np.isnan(value) and metric != 'ipc':
                        run_agg[metric] += value
                        has_valid_tasks = True
            
            if has_valid_tasks:
                # Recalculate Derived Metrics for the Aggregate
                if run_agg.get('cycles', 0) > 0:
                    run_agg['ipc'] = run_agg.get('instructions', 0) / run_agg['cycles']
                else:
                    run_agg['ipc'] = np.nan
                
                # Store Aggregated Data
                for metric, value in run_agg.items():
                    all_data[bench_type]['Aggregated'][metric].append(value)

    return all_data

# ==============================================================================
# 2. VISUALIZATION LOGIC
# ==============================================================================

def visualize_task(data_for_task, task_name, output_dir):
    """Generates plots for a specific task or aggregated view."""
    
    if len(data_for_task) < 2:
        return # Need at least 2 benchmarks to compare

    # Create a clean subfolder for this task to avoid file clutter
    clean_task = task_name.replace(" ", "_")
    task_subdir = os.path.join(output_dir, clean_task)
    os.makedirs(task_subdir, exist_ok=True)

    labels = sorted(data_for_task.keys())
    # Heuristic: Make "Baseline" the first label (Blue)
    if "Baseline" in labels[1] or "thinlto" in labels[1]:
         labels.reverse()
    label1, label2 = labels[0], labels[1]

    # Get list of metrics available for this task
    available_metrics = sorted(list(set(data_for_task[label1].keys()) | set(data_for_task[label2].keys())))

    # Priorities for display
    PRIORITY_METRICS = ['instructions', 'cycles', 'ipc', 'l1_icache_load_misses', 'itlb_load_misses', 'sysbench_tps']
    
    # Filter to only show interesting metrics present in data
    metrics_to_plot = [m for m in PRIORITY_METRICS if m in available_metrics]

    print(f"\n📊 Generating plots for: {task_name} (in {clean_task}/)...")

    for metric in metrics_to_plot:
        raw1 = np.array(data_for_task[label1].get(metric, [])).astype(float)
        raw2 = np.array(data_for_task[label2].get(metric, [])).astype(float)
        
        # Remove NaNs
        raw1 = raw1[~np.isnan(raw1)]
        raw2 = raw2[~np.isnan(raw2)]

        if len(raw1) == 0 or len(raw2) == 0:
            continue

        # Scaling
        scale = 1.0
        unit = ""
        if metric in ['cycles', 'instructions']:
            scale = 1e9; unit = "(Billions)"
        elif "misses" in metric:
            scale = 1e6; unit = "(Millions)"
        elif "tps" in metric:
            unit = "(Tx/s)"

        # T-Test
        t_stat, p_val = stats.ttest_ind(raw1, raw2, equal_var=False)
        p_text = f"p={p_val:.4f}"
        sig_text = "SIGNIFICANT" if p_val < 0.05 else "Not Significant"

        # --- PLOTTING ---
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 5))
        title = f"{task_name} | {metric} {unit}"
        fig.suptitle(title, fontsize=14, fontweight='bold', y=1.05)

        # 1. Line Plot (Stability over iterations)
        ax1.plot(raw1 / scale, 'o-', label=label1, alpha=0.8)
        ax1.plot(raw2 / scale, 's-', label=label2, alpha=0.8)
        ax1.set_title("Run-to-Run Stability")
        ax1.set_xlabel("Iteration")
        ax1.set_ylabel(f"Value {unit}")
        ax1.legend()
        ax1.grid(True, linestyle='--', alpha=0.5)

        # 2. Bar Plot (Mean comparison with CI)
        plot_df = pd.DataFrame({
            'Benchmark': [label1] * len(raw1) + [label2] * len(raw2),
            'Value': np.concatenate([raw1 / scale, raw2 / scale])
        })
        
        sns.barplot(ax=ax2, x='Benchmark', y='Value', data=plot_df, capsize=0.1, errorbar=('ci', 95))
        
        # Calculate Delta
        m1, m2 = np.mean(raw1), np.mean(raw2)
        diff_pct = ((m2 - m1) / m1) * 100
        
        # Determine color based on "Good" or "Bad"
        color = 'green' if p_val < 0.05 else 'gray'
        # Logic: Lower is better for instructions/cycles/misses; Higher is better for TPS/IPC
        is_lower_better = any(x in metric for x in ['instructions', 'cycles', 'misses', 'time'])
        if is_lower_better:
            if diff_pct < 0 and p_val < 0.05: color = 'green' # Good (Reduction)
            elif diff_pct > 0 and p_val < 0.05: color = 'red' # Bad (Regression)
        else:
            if diff_pct > 0 and p_val < 0.05: color = 'green' # Good (Increase)
            elif diff_pct < 0 and p_val < 0.05: color = 'red' # Bad (Decrease)

        ax2.set_title(f"Mean Comparison (Delta: {diff_pct:+.2f}%)")
        ax2.text(0.5, 0.9, f"{p_text}\n{sig_text}", transform=ax2.transAxes, 
                 ha='center', color=color, fontweight='bold',
                 bbox=dict(facecolor='white', alpha=0.8, edgecolor=color))
        ax2.set_ylabel(f"Mean {unit}")

        plt.tight_layout()
        
        # Save File
        # Clean filename: just the metric name, since it's inside the task folder
        filename = f"{metric}.png"
        save_path = os.path.join(task_subdir, filename)
        plt.savefig(save_path, dpi=150, bbox_inches='tight')
        print(f"  -> Saved: {clean_task}/{filename}")
        plt.close()

# ==============================================================================
# 3. MAIN EXECUTION
# ==============================================================================

if __name__ == "__main__":
    if not os.path.isdir(RESULTS_DIR):
        print(f"❌ Error: Results directory not found: {RESULTS_DIR}")
        sys.exit(1)

    print(f"🚀 Parsing results from: {RESULTS_DIR}")
    all_data = analyze_directory(RESULTS_DIR)

    if not all_data:
        print("No data found.")
        sys.exit(0)

    # Create a 'plots' subdirectory
    plots_dir = os.path.join(RESULTS_DIR, "plots")
    os.makedirs(plots_dir, exist_ok=True)
    print(f"📂 Saving plots to: {plots_dir}")

    # Identify available tasks (indices + 'Aggregated')
    first_bench = list(all_data.keys())[0]
    keys = list(all_data[first_bench].keys())
    
    # Sort keys: Integers first (tasks), then 'Aggregated'
    task_indices = sorted([k for k in keys if isinstance(k, int)])
    has_aggregated = 'Aggregated' in keys

    # 1. Visualize Individual Tasks
    for i in task_indices:
        t_name = TASK_NAMES[i] if i < len(TASK_NAMES) else f"Task_{i}"
        
        data_subset = {}
        for bench_type in all_data.keys():
            if i in all_data[bench_type]:
                data_subset[bench_type] = all_data[bench_type][i]
        
        visualize_task(data_subset, t_name, plots_dir)

    # 2. Visualize Aggregated
    if has_aggregated:
        data_subset = {}
        for bench_type in all_data.keys():
            if 'Aggregated' in all_data[bench_type]:
                data_subset[bench_type] = all_data[bench_type]['Aggregated']
        
        visualize_task(data_subset, "Total_Aggregated", plots_dir)

    print("\n✅ Visualization Complete.")