import os
import re
import sys
import argparse
from collections import defaultdict
import numpy as np
from scipy import stats

# --- Task Names from the Shell Script ---
TASK_NAMES = [
    'oltp_read_write',
    'oltp_update_index',
    'oltp_delete',
    'select_random_ranges',
    # 'oltp_read_only'
]

# --- Helper to batch/bin data ---
def batch_list(data, batch_size):
    """
    Sums data in chunks of batch_size.
    """
    if batch_size <= 1:
        return data
    
    batched_data = []
    for i in range(0, len(data), batch_size):
        chunk = data[i:i + batch_size]
        if len(chunk) == batch_size:
            batched_data.append(sum(chunk))
            
    return batched_data

def get_perf_patterns():
    """Defines and returns the metric patterns."""
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
    """Parses a single 'perf stat' report block and calculates derived metrics."""
    metrics = defaultdict(float)
    
    for key, pattern in patterns.items():
        match = pattern.search(report_content)
        if match:
            try:
                val = float(match.group(1).replace(',', ''))
                metrics[key] = val
            except (ValueError, IndexError):
                pass

    if metrics.get('cycles', 0) > 0:
        metrics['ipc'] = metrics.get('instructions', 0) / metrics['cycles']
    
    if 'sys_time_s' in metrics and 'user_time_s' in metrics:
        metrics['server_cpu_time_s'] = metrics['sys_time_s'] + metrics['user_time_s']
    
    # Clean up raw time components to keep report clean
    metrics.pop('user_time_s', None)
    metrics.pop('sys_time_s', None)
    
    if any(k in metrics for k in ['instructions', 'cycles', 'server_cpu_time_s']):
        return dict(metrics)
    return None

def parse_perf_data(stderr_content, task_by_task=False):
    """
    Parses stderr, which contains multiple 'perf stat' reports.
    """
    patterns = get_perf_patterns()
    perf_reports = re.split(r'--- Perf for', stderr_content)
    
    parsed_reports = []
    
    # Skip the first split result (before the first header)
    for report in perf_reports[1:]: 
        if any(char.isdigit() for char in report):
            metrics = process_single_perf_report(report, patterns)
            if metrics:
                parsed_reports.append(metrics)
            
    if not parsed_reports:
        nan_metrics = {k: np.nan for k in patterns.keys()}
        nan_metrics['ipc'] = np.nan
        nan_metrics['server_cpu_time_s'] = np.nan
        return [nan_metrics] if task_by_task else nan_metrics

    if task_by_task:
        return parsed_reports
    else:
        # SUM all metrics for Run-by-Run mode
        summed_metrics = defaultdict(float)
        count = 0
        for report_metrics in parsed_reports:
            count += 1
            for key, val in report_metrics.items():
                if not np.isnan(val):
                    # IPC cannot be summed directly, it must be re-calculated or averaged
                    if key == 'ipc': 
                        continue
                    summed_metrics[key] += val
        
        # Recalculate total IPC correctly
        if summed_metrics.get('cycles', 0) > 0:
            summed_metrics['ipc'] = summed_metrics.get('instructions', 0) / summed_metrics['cycles']
            
        return dict(summed_metrics)

def parse_sysbench_logs(stdout_content, task_by_task=False):
    """
    Parses the stdout for sysbench TPS.
    """
    try:
        tps_matches = re.findall(r'transactions:\s+.*\((.*) per sec\.\)', stdout_content)
        tps_values = [float(tps) for tps in tps_matches]

        if task_by_task:
            return [{'sysbench_tps_task': tps} for tps in tps_values]
        else:
            return {'sysbench_total_tps': sum(tps_values)}
            
    except Exception:
        if task_by_task:
            return [{'sysbench_tps_task': np.nan}]
        else:
            return {'sysbench_total_tps': np.nan}


def analyze_directory(results_dir, task_by_task=False):
    """Analyzes all benchmark subdirectories."""
    all_data = defaultdict(lambda: defaultdict(lambda: defaultdict(list))) 
    
    items = os.listdir(results_dir)
    benchmark_types = [d for d in items if os.path.isdir(os.path.join(results_dir, d))]
    
    if not benchmark_types:
        print(f"No subdirectories found in {results_dir}")
        return all_data

    for bench_type in benchmark_types:
        bench_path = os.path.join(results_dir, bench_type)
        run_files = sorted([f for f in os.listdir(bench_path) if f.startswith('run_')])

        print(f"📁 Analyzing {len(run_files)} runs in directory: {bench_type}")

        for run_file in run_files:
            file_path = os.path.join(bench_path, run_file)
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except Exception as e:
                print(f"  [!] WARNING: Could not read file {file_path}: {e}")
                continue

            stdout_match = re.search(r'--- Script Output \(stdout\) ---\n(.*?)\n\n--- Perf Report \(stderr\)', content, re.DOTALL)
            stderr_match = re.search(r'--- Perf Report \(stderr\) ---\n(.*)', content, re.DOTALL)

            if not stdout_match or not stderr_match:
                continue
                
            stdout_content = stdout_match.group(1)
            stderr_content = stderr_match.group(1)

            perf_metrics_result = parse_perf_data(stderr_content, task_by_task)
            sysbench_metrics_result = parse_sysbench_logs(stdout_content, task_by_task)
            
            if task_by_task:
                num_perf_tasks = len(perf_metrics_result)
                num_sysbench_tasks = len(sysbench_metrics_result)
                num_tasks = min(num_perf_tasks, num_sysbench_tasks)

                # Validation Warning
                if num_tasks != len(TASK_NAMES) and num_tasks > 0:
                     # Only warn once per run file to avoid spam
                     pass 
                
                for i in range(num_tasks):
                    all_metrics = {**perf_metrics_result[i], **sysbench_metrics_result[i]}
                    for key, value in all_metrics.items():
                        all_data[bench_type][i][key].append(value)
                        
            else:
                all_metrics = {**perf_metrics_result, **sysbench_metrics_result}
                for key, value in all_metrics.items():
                    all_data[bench_type][0][key].append(value)
            
    return all_data


def print_analysis(data, batch_size=1, task_by_task=False):
    """Prints the final analysis report."""
    report_lines = []

    if len(data) < 2:
        return "Error: Need at least two benchmark types to compare."

    # Ensure Baseline is label1 if possible for consistent diff calculation
    labels = sorted(data.keys())
    # Simple heuristic: try to make "Baseline" the first label
    if "Baseline" in labels[1] or "thinlto" in labels[1]:
         labels.reverse()
         
    label1, label2 = labels[0], labels[1]
    
    task_keys = sorted(list(data[label1].keys())) 
    
    CORE_METRICS = [
        'instructions', 'cycles', 'ipc', 'l1_icache_load_misses', 
        'itlb_load_misses', 'server_cpu_time_s', 'sysbench_total_tps', 
        'sysbench_tps_task'
    ]

    report_lines.append("\n" + "="*80)
    report_lines.append(f"Performance Analysis: '{label1}' (Base) vs '{label2}' (New)")
    if task_by_task:
        report_lines.append(f"MODE: Task-by-Task comparison.")
    else:
        report_lines.append("MODE: Run-by-Run comparison (metrics summed per run).")
        
    if batch_size > 1:
        report_lines.append(f"NOTE: Data batched (summed) in groups of {batch_size}.")
    report_lines.append("="*80)
    
    for task_index in task_keys:
        
        if task_by_task:
            task_name = TASK_NAMES[task_index] if task_index < len(TASK_NAMES) else f"Task #{task_index + 1}"
            task_label = task_name.replace('_', ' ').title()
            
            report_lines.append("\n" + "#"*70)
            report_lines.append(f"### 🎯 Task Report: {task_label} ###")
            report_lines.append("#"*70)
        
        task_data1 = data[label1].get(task_index, {})
        task_data2 = data[label2].get(task_index, {})
        
        if not task_data1 and not task_data2:
            continue
            
        available_metrics = set(task_data1.keys()) | set(task_data2.keys())
        metrics_to_display = [m for m in CORE_METRICS if m in available_metrics]
            
        for metric in metrics_to_display:
            raw1 = task_data1.get(metric, [])
            raw2 = task_data2.get(metric, [])

            raw1 = [x for x in raw1 if not np.isnan(x)]
            raw2 = [x for x in raw2 if not np.isnan(x)]

            if not raw1 or not raw2:
                continue

            data1 = np.array(batch_list(raw1, batch_size)).astype(float)
            data2 = np.array(batch_list(raw2, batch_size)).astype(float)

            report_lines.append(f"\n--- Metric: {metric.replace('_', ' ').title()} ---")
            
            if len(data1) < 2 or len(data2) < 2:
                report_lines.append(f"Not enough samples. (Found {len(data1)} vs {len(data2)})")
                continue
            
            # Smart Scaling
            if metric in ['cycles', 'instructions']:
                scale, unit = 1e9, "B"
            elif "misses" in metric:
                scale, unit = 1e6, "M"
            elif metric == 'ipc':
                scale, unit = 1, "I/C"
            elif 'time_s' in metric:
                scale, unit = 1, "s"
            elif 'tps' in metric or 'task' in metric:
                scale, unit = 1, "Tx/s"
            else:
                scale, unit = 1, ""
            
            mean1, std1 = np.mean(data1) / scale, np.std(data1) / scale
            mean2, std2 = np.mean(data2) / scale, np.std(data2) / scale
            
            # Statistical Test
            with np.errstate(divide='ignore', invalid='ignore'):
                t_stat, p_value = stats.ttest_ind(data1, data2, equal_var=False, nan_policy='omit')
            
            if np.isnan(p_value): p_value = 1.0

            # Formula: (New - Base) / Base * 100
            # Positive = New is bigger. Negative = New is smaller.
            if mean1 != 0:
                diff_pct = ((mean2 - mean1) / mean1) * 100
            else:
                diff_pct = 0.0

            # --- INTERPRETATION LOGIC ---
            # For these metrics, LOWER (Negative Diff) is BETTER
            lower_is_better = ['cycles', 'instructions', 'misses', 'time_s']
            # For these metrics, HIGHER (Positive Diff) is BETTER
            higher_is_better = ['ipc', 'tps']
            
            is_good = False
            if any(x in metric for x in lower_is_better):
                if diff_pct < 0: is_good = True
            elif any(x in metric for x in higher_is_better):
                if diff_pct > 0: is_good = True
            
            verdict = ""
            if p_value < 0.05:
                verdict = "[WIN]" if is_good else "[LOSS]"
            
            report_lines.append(f"{'':<25} | {'Mean ('+unit+')':>15} | {'Std Dev':>10} | {'N'}")
            report_lines.append("-"*65)
            report_lines.append(f"{label1:<25} | {mean1:>15.4f} | {std1:>10.4f} | {len(data1)}")
            report_lines.append(f"{label2:<25} | {mean2:>15.4f} | {std2:>10.4f} | {len(data2)}")
            
            report_lines.append(f"\nDiff: {diff_pct:+.2f}%  (p={p_value:.4f})  {verdict}")

            if p_value < 0.05:
                report_lines.append(">> STATISTICALLY SIGNIFICANT difference.")
            else:
                report_lines.append(">> NOT statistically significant.")
                
    report_lines.append("\n" + "="*80)
    
    return "\n".join(report_lines)

def main():
    parser = argparse.ArgumentParser(description="Analyze benchmark results.")
    parser.add_argument("results_dir", help="Path to the top-level benchmark results directory.")
    parser.add_argument("--batch-size", type=int, default=1, help="Number of samples to sum into a single batch.")
    parser.add_argument("--task-by-task", action='store_true', 
                        help="Perform t-test on individual task metrics instead of total run metrics.")
    args = parser.parse_args()

    if not os.path.isdir(args.results_dir):
        print(f"Error: Directory not found at '{os.path.abspath(args.results_dir)}'")
        sys.exit(1)
        
    all_benchmark_data = analyze_directory(args.results_dir, args.task_by_task)
    
    if not all_benchmark_data:
        print("No benchmark data found to analyze.")
        return

    report = print_analysis(all_benchmark_data, args.batch_size, args.task_by_task)
    print(report)

    mode_suffix = "task" if args.task_by_task else "run"
    analysis_output_path = os.path.join(args.results_dir, f'analysis_{mode_suffix}_batch{args.batch_size}.txt')
    with open(analysis_output_path, 'w') as f:
        f.write(report)
    print(f"📂 Saving report to {analysis_output_path}")

if __name__ == "__main__":
    main()