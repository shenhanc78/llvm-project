import os
import re
import sys
import argparse
from collections import defaultdict
import numpy as np
from scipy import stats

def parse_perf_data(stderr_content):
    """
    Parses stderr, which contains multiple 'perf stat' reports.
    It finds all reports, sums the metrics, and returns the totals.
    """
    metrics = defaultdict(float)
    patterns = {
        'instructions': re.compile(r'([\d,]+)\s+instructions'),
        'cycles': re.compile(r'([\d,]+)\s+cycles'),
        'itlb_load_misses': re.compile(r'([\d,]+)\s+iTLB-load-misses'),
        'l1_icache_load_misses': re.compile(r'([\d,]+)\s+L1-icache-load-misses'),
        'l1_dcache_load_misses': re.compile(r'([\d,]+)\s+L1-dcache-load-misses'),
        'llc_load_misses': re.compile(r'([\d,]+)\s+LLC-load-misses'),
        'wall_time_s': re.compile(r'(\d+\.\d+)\s+seconds time elapsed'),
        'user_time_s': re.compile(r'(\d+\.\d+)\s+seconds user'),
        'sys_time_s' : re.compile(r'(\d+\.\d+)\s+seconds sys'),
        'branch_misses': re.compile(r'([\d,]+)\s+branch-misses'),
    }

    # Split the stderr into individual 'perf stat' reports
    # Each report starts with '--- Perf for ...'
    perf_reports = re.split(r'--- Perf for', stderr_content)
    
    num_reports = 0
    for report in perf_reports:
        if not report:
            continue
        
        # Check if the report contains any numbers, otherwise it's just text
        if not any(char.isdigit() for char in report):
            continue
            
        num_reports += 1
        for key, pattern in patterns.items():
            match = pattern.search(report)
            if match:
                try:
                    metrics[key] += float(match.group(1).replace(',', ''))
                except (ValueError, IndexError):
                    pass # This metric just won't be incremented
            
    if num_reports == 0: # No perf data found
        return {k: np.nan for k in patterns.keys()}

    # Calculate derived metrics from the totals
    if 'cycles' in metrics and metrics['cycles'] > 0:
        metrics['ipc'] = metrics.get('instructions', 0) / metrics['cycles']
    
    if 'sys_time_s' in metrics and 'user_time_s' in metrics:
        metrics['sys_user_total_time_s'] = metrics.get('sys_time_s', 0) + metrics.get('user_time_s', 0)

    # Note: We sum 'wall_time_s' from all 5 perf runs. This is correct.
    return metrics

def parse_sysbench_logs(stdout_content):
    """
    Parses the stdout, which contains multiple sysbench logs.
    It finds all 'transactions per sec' and 'total time' lines, aggregates
    them, and returns the totals.
    """
    metrics = {}
    try:
        tps_matches = re.findall(r'transactions:\s+.*\((.*) per sec\.\)', stdout_content)
        time_matches = re.findall(r'total time:\s+(.*)s', stdout_content)

        total_tps = sum(float(tps) for tps in tps_matches)
        total_time = sum(float(t) for t in time_matches)
        
        metrics['sysbench_total_tps'] = total_tps
        metrics['sysbench_total_time_s'] = total_time
        
    except Exception as e:
        print(f"  [!] WARNING: Could not parse sysbench logs: {e}")
        metrics['sysbench_total_tps'] = np.nan
        metrics['sysbench_total_time_s'] = np.nan
        
    return metrics


def analyze_directory(results_dir):
    """Analyzes all benchmark subdirectories."""
    all_data = defaultdict(lambda: defaultdict(list))
    benchmark_types = [d for d in os.listdir(results_dir) if os.path.isdir(os.path.join(results_dir, d))]
    
    for bench_type in benchmark_types:
        bench_path = os.path.join(results_dir, bench_type)
        run_files = sorted([f for f in os.listdir(bench_path) if f.startswith('run_') and f.endswith('.txt')])

        for run_file in run_files:
            file_path = os.path.join(bench_path, run_file)
            
            # Read the whole log file
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
            except Exception as e:
                print(f"  [!] WARNING: Could not read file {file_path}: {e}")
                continue

            # Split into stdout (from sysbench) and stderr (from perf stat)
            stdout_match = re.search(r'--- Script Output \(stdout\) ---\n(.*?)\n\n--- Perf Report \(stderr\)', content, re.DOTALL)
            stderr_match = re.search(r'--- Perf Report \(stderr\) ---\n(.*)', content, re.DOTALL)

            if not stdout_match or not stderr_match:
                print(f"  [!] WARNING: Could not parse stdout/stderr split in {file_path}")
                continue
                
            stdout_content = stdout_match.group(1)
            stderr_content = stderr_match.group(1)

            # Parse both sections and combine the metrics
            perf_metrics = parse_perf_data(stderr_content)
            sysbench_metrics = parse_sysbench_logs(stdout_content)
            
            all_metrics = {**perf_metrics, **sysbench_metrics}
            
            for key, value in all_metrics.items():
                all_data[bench_type][key].append(value)
    
    return all_data

def print_analysis(data):
    """Prints the final analysis report, handling missing data gracefully."""
    report_lines = []

    if len(data) < 2:
        report_lines.append("\n" + "="*80)
        report_lines.append("Error: Could not find at least two benchmark types with valid data to compare.")
        report_lines.append(f"Found types with any data: {list(data.keys())}")
        report_lines.append("Please ensure the provided directory contains at least two subdirectories with valid result files.")
        report_lines.append("="*80)
        return "\n".join(report_lines)

    labels = sorted(data.keys())
    label1, label2 = labels[0], labels[1]
    
    report_lines.append("\n" + "="*80)
    report_lines.append(f"Performance Analysis: '{label1}' vs '{label2}'")
    report_lines.append("="*80)
    
    metrics_of_interest = set(data[label1].keys()) | set(data[label2].keys())
    
    for metric in sorted(metrics_of_interest):
        data1 = np.array(data[label1].get(metric, [])).astype(float)
        data1 = data1[~np.isnan(data1)]
        data2 = np.array(data[label2].get(metric, [])).astype(float)
        data2 = data2[~np.isnan(data2)]

        report_lines.append(f"\n--- Metric: {metric.replace('_', ' ').title()} ---")
        
        if len(data1) < 2 or len(data2) < 2:
            report_lines.append(f"Not enough valid data points for a meaningful comparison. (Found {len(data1)} for {label1}, {len(data2)} for {label2})")
            continue
        
        # Scale large numbers for readability
        if metric in ['cycles', 'instructions']:
            scale, unit = 1e9, "B" # Billions
        elif "misses" in metric:
            scale, unit = 1e6, "M" # Millions
        else:
            scale, unit = 1, ""
        
        mean1, std1 = np.mean(data1) / scale, np.std(data1) / scale
        mean2, std2 = np.mean(data2) / scale, np.std(data2) / scale
        
        # Handle division by zero for std dev if all values are identical
        with np.errstate(divide='ignore', invalid='ignore'):
            t_stat, p_value = stats.ttest_ind(data1, data2, equal_var=False, nan_policy='omit')
        
        if np.isnan(p_value):
            p_value = 1.0 if np.isclose(mean1, mean2) else 0.0

        report_lines.append(f"{'':<25} | {'Mean ('+unit+')':>15} | {'Std Dev ('+unit+')':>15} | {'Valid Runs'}")
        report_lines.append("-"*70)
        report_lines.append(f"{label1:<25} | {mean1:>15.4f} | {std1:>15.4f} | {len(data1)}")
        report_lines.append(f"{label2:<25} | {mean2:>15.4f} | {std2:>15.4f} | {len(data2)}")
        report_lines.append("")  # For the blank line
        report_lines.append(f"T-test: p-value = {p_value:.4f}")

        if p_value < 0.05:
            report_lines.append("Conclusion: The difference is STATISTICALLY SIGNIFICANT.")
            # Lower is better for time and misses
            if "time" in metric or "misses" in metric:
                better_label, worse_label = (label1, label2) if mean1 < mean2 else (label2, label1)
                direction = "FASTER" if "time" in metric else "BETTER (fewer misses)"
            else: # Higher is better for IPC and TPS
                better_label, worse_label = (label1, label2) if mean1 > mean2 else (label2, label1)
                direction = "BETTER (higher is better)"

            report_lines.append(f"'{better_label}' is significantly {direction.lower()} than '{worse_label}'.")
        else:
            report_lines.append("Conclusion: The difference is NOT statistically significant.")
            
    report_lines.append("\n" + "="*80)
    
    return "\n".join(report_lines)


def main():
    parser = argparse.ArgumentParser(description="Analyze benchmark results from perf.")
    parser.add_argument("results_dir", help="Path to the top-level benchmark results directory.")
    args = parser.parse_args()

    if not os.path.isdir(args.results_dir):
        print(f"Error: Directory not found at '{os.path.abspath(args.results_dir)}'")
        sys.exit(1)
        
    all_benchmark_data = analyze_directory(args.results_dir)
    report = print_analysis(all_benchmark_data)
    print(report)

    analysis_output_path = os.path.join(args.results_dir, 'analysis.txt')
    with open(analysis_output_path, 'w') as f:
        f.write(report)
    print(f"📂 Saving report to {analysis_output_path}")

if __name__ == "__main__":
    main()