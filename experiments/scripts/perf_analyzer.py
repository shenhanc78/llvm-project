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
        'branch_misses_percent': re.compile(r'(\d+\.\d+)%\s+of all branches'),
        'wall_time_s': re.compile(r'(\d+\.\d+)\s+seconds time elapsed')
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
            parsed_metrics = parse_perf_data(file_path)
            for key, value in parsed_metrics.items():
                all_data[bench_type][key].append(value)
    
    return all_data

def print_analysis(data):
    """Prints the final analysis report, handling missing data gracefully."""
    if len(data) < 2:
        print("\n" + "="*80)
        print(f"Error: Could not find at least two benchmark types with valid data to compare.")
        print(f"Found types with any data: {list(data.keys())}")
        print("Please ensure the provided directory contains at least two subdirectories with valid result files.")
        print("="*80)
        return

    labels = sorted(data.keys())
    label1, label2 = labels[0], labels[1]
    print("\n" + "="*80)
    print(f"Performance Analysis: '{label1}' vs '{label2}'")
    print("="*80)
    
    metrics_of_interest = list(data[label1].keys())
    
    for metric in metrics_of_interest:
        data1 = np.array(data[label1].get(metric, [])).astype(float)
        data1 = data1[~np.isnan(data1)]
        data2 = np.array(data[label2].get(metric, [])).astype(float)
        data2 = data2[~np.isnan(data2)]

        print(f"\n--- Metric: {metric.replace('_', ' ').title()} ---")
        
        if len(data1) < 2 or len(data2) < 2:
            print(f"Not enough valid data points for a meaningful comparison. (Found {len(data1)} for {label1}, {len(data2)} for {label2})")
            continue
        
        scale = 1e12 if metric in ['cycles', 'instructions'] else 1e9 if "misses" in metric else 1
        
        mean1, std1 = np.mean(data1) / scale, np.std(data1) / scale
        mean2, std2 = np.mean(data2) / scale, np.std(data2) / scale
        t_stat, p_value = stats.ttest_ind(data1, data2, equal_var=False, nan_policy='omit')

        print(f"{'':<25} | {'Mean':>15} | {'Std Dev':>15} | {'Valid Runs'}")
        print("-"*70)
        print(f"{label1:<25} | {mean1:>15.4f} | {std1:>15.4f} | {len(data1)}")
        print(f"{label2:<25} | {mean2:>15.4f} | {std2:>15.4f} | {len(data2)}")
        print()
        print(f"T-test: p-value = {p_value:.4f}")

        if p_value < 0.05:
            print("Conclusion: The difference is STATISTICALLY SIGNIFICANT.")
            direction = "FASTER" if "time" in metric else "MORE EFFICIENT"
            direction = "WORSE" if "misses" in metric else direction
            better_label, worse_label = (label1, label2) if mean1 < mean2 else (label2, label1)
            if "misses" in metric: better_label, worse_label = worse_label, better_label
            print(f"'{better_label}' is significantly {direction.lower()} than '{worse_label}'.")
        else:
            print("Conclusion: The difference is NOT statistically significant.")
    print("\n" + "="*80)


def main():
    parser = argparse.ArgumentParser(description="Analyze benchmark results from perf.")
    parser.add_argument("results_dir", help="Path to the top-level benchmark results directory.")
    args = parser.parse_args()

    if not os.path.isdir(args.results_dir):
        print(f"Error: Directory not found at '{os.path.abspath(args.results_dir)}'")
        sys.exit(1)
        
    all_benchmark_data = analyze_directory(args.results_dir)
    print_analysis(all_benchmark_data)

if __name__ == "__main__":
    main()