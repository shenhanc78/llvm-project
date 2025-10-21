# final_analyzer.py
import os
import re
import sys
import argparse
from collections import defaultdict
import numpy as np
from scipy import stats

def parse_perf_data(file_path):
    """Parses a single perf output file, correctly handling UTF-16LE encoding."""
    content = None
    # Auto-detect encoding
    for enc in ['utf-8', 'utf-16-le', 'latin-1']:
        try:
            with open(file_path, 'r', encoding=enc) as f:
                content = f.read()
            break
        except (UnicodeDecodeError, TypeError):
            continue
    
    if content is None:
        print(f"  [!] WARNING: Could not decode file {os.path.basename(file_path)} with any standard encoding.")
        return {}

    metrics = {}
    patterns = {
        'instructions': re.compile(r'([\d,]+)\s+instructions'),
        'cycles': re.compile(r'([\d,]+)\s+cycles'),
        'ipc': re.compile(r'(\d+\.\d+)\s+insn per cycle'),
        'itlb_load_misses': re.compile(r'([\d,]+)\s+iTLB-load-misses'),
        'l1_icache_load_misses': re.compile(r'([\d,]+)\s+L1-icache-load-misses'),
        'wall_time_s': re.compile(r'(\d+\.\d+)\s+seconds time elapsed'),
        'user_time_s': re.compile(r'(\d+\.\d+)\s+seconds user'),
        'sys_time_s' : re.compile(r'(\d+\.\d+)\s+seconds sys'),
    }

    for key, pattern in patterns.items():
        match = pattern.search(content)
        if match:
            try:
                metrics[key] = float(match.group(1).replace(',', ''))
            except (ValueError, IndexError):
                metrics[key] = np.nan
        else:
            metrics[key] = np.nan
    
    metrics['sys_user_total_time_s'] = metrics['sys_time_s'] + metrics['user_time_s']

    return metrics

def analyze_directory(results_dir):
    """Analyzes all benchmark subdirectories."""
    all_data = defaultdict(lambda: defaultdict(list))
    benchmark_types = [d for d in os.listdir(results_dir) if os.path.isdir(os.path.join(results_dir, d))]
    
    for bench_type in benchmark_types:
        bench_path = os.path.join(results_dir, bench_type)
        run_files = sorted([f for f in os.listdir(bench_path) if f.startswith('run_') and f.endswith('.txt')])

        for run_file in run_files:
            if run_file == 'run_1.txt':
                continue
            file_path = os.path.join(bench_path, run_file)
            parsed_metrics = parse_perf_data(file_path)
            for key, value in parsed_metrics.items():
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
    
    metrics_of_interest = list(data[label1].keys())
    
    for metric in metrics_of_interest:
        data1 = np.array(data[label1].get(metric, [])).astype(float)
        data1 = data1[~np.isnan(data1)]
        data2 = np.array(data[label2].get(metric, [])).astype(float)
        data2 = data2[~np.isnan(data2)]

        report_lines.append(f"\n--- Metric: {metric.replace('_', ' ').title()} ---")
        
        if len(data1) < 2 or len(data2) < 2:
            report_lines.append(f"Not enough valid data points for a meaningful comparison. (Found {len(data1)} for {label1}, {len(data2)} for {label2})")
            continue
        
        scale = 1e12 if metric in ['cycles', 'instructions'] else 1e9 if "misses" in metric else 1
        
        mean1, std1 = np.mean(data1) / scale, np.std(data1) / scale
        mean2, std2 = np.mean(data2) / scale, np.std(data2) / scale
        t_stat, p_value = stats.ttest_ind(data1, data2, equal_var=False, nan_policy='omit')

        report_lines.append(f"{'':<25} | {'Mean':>15} | {'Std Dev':>15} | {'Valid Runs'}")
        report_lines.append("-"*70)
        report_lines.append(f"{label1:<25} | {mean1:>15.4f} | {std1:>15.4f} | {len(data1)}")
        report_lines.append(f"{label2:<25} | {mean2:>15.4f} | {std2:>15.4f} | {len(data2)}")
        report_lines.append("")  # For the blank line
        report_lines.append(f"T-test: p-value = {p_value:.4f}")

        if p_value < 0.05:
            report_lines.append("Conclusion: The difference is STATISTICALLY SIGNIFICANT.")
            direction = "FASTER" if "time" in metric else "MORE EFFICIENT"
            direction = "WORSE" if "misses" in metric else direction
            better_label, worse_label = (label1, label2) if mean1 < mean2 else (label2, label1)
            if "misses" in metric: better_label, worse_label = worse_label, better_label
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