import os
import re
import sys
import argparse
from collections import defaultdict
import numpy as np
from scipy import stats

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
            # For TPS, we usually want the MEAN of the batch to represent the period,
            # but since we are comparing totals, Sum vs Mean matters less as long as consistency is kept.
            # However, standard sysbench practice over time is usually average. 
            # Let's stick to SUM to remain consistent with the previous logic of "accumulating" work.
            batched_data.append(sum(chunk))
            
    return batched_data

def parse_sysbench_logs(content):
    """
    Parses the entire log file content to find all sysbench outputs.
    Sums the TPS of all sub-tests (RW, Update, Delete, etc.) in that single run.
    """
    metrics = {}
    try:
        # We scan the whole file (stdout part) for every occurrence of "transactions: ... (X per sec.)"
        # This matches the standard sysbench output format.
        tps_matches = re.findall(r'transactions:\s+.*\(([\d\.]+) per sec\.\)', content)
        
        if not tps_matches:
            return {'sysbench_total_tps': np.nan}

        # Sum TPS across all individual sysbench tests in this specific run file
        total_tps = sum(float(tps) for tps in tps_matches)
        metrics['sysbench_total_tps'] = total_tps
        
    except Exception as e:
        print(f"  [!] WARNING: Could not parse sysbench logs: {e}")
        metrics['sysbench_total_tps'] = np.nan
        
    return metrics

def analyze_directory(results_dir):
    """Analyzes all benchmark subdirectories."""
    all_data = defaultdict(lambda: defaultdict(list))
    
    # Only process directories
    if not os.path.exists(results_dir):
        print(f"Error: Directory {results_dir} does not exist.")
        return all_data

    items = os.listdir(results_dir)
    benchmark_types = [d for d in items if os.path.isdir(os.path.join(results_dir, d))]
    
    if not benchmark_types:
        print(f"No subdirectories found in {results_dir}")
        return all_data

    for bench_type in benchmark_types:
        bench_path = os.path.join(results_dir, bench_type)
        # Filter for run_X.txt files
        run_files = sorted([f for f in os.listdir(bench_path) if f.startswith('run_') and f.endswith('.txt')])

        for run_file in run_files:
            file_path = os.path.join(bench_path, run_file)
            
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except Exception as e:
                print(f"  [!] WARNING: Could not read file {file_path}: {e}")
                continue

            # Robust string splitting instead of Regex to isolate stdout
            # The runner formats it as:
            # --- Script Output (stdout) ---
            # [DATA]
            # --- Perf Report (stderr) ---
            
            try:
                # Split after the stdout header
                parts = content.split('--- Script Output (stdout) ---')
                if len(parts) < 2:
                    print(f"  [!] WARNING: Malformed log file (missing stdout header): {run_file}")
                    continue
                
                # Take everything after the header, but stop before the stderr header
                stdout_content = parts[1].split('--- Perf Report (stderr) ---')[0]
                
                metrics = parse_sysbench_logs(stdout_content)
                
                for key, value in metrics.items():
                    all_data[bench_type][key].append(value)

            except Exception as e:
                print(f"  [!] Error parsing structure of {run_file}: {e}")

    return all_data

def print_analysis(data, batch_size=1):
    """Prints the final analysis report."""
    report_lines = []

    if len(data) < 2:
        return "Error: Need at least two benchmark types to compare."

    # Sort keys to ensure consistent order (e.g., Baseline vs PreserveNone)
    labels = sorted(data.keys())
    label1, label2 = labels[0], labels[1]
    
    report_lines.append("\n" + "="*80)
    report_lines.append(f"   TPS Analysis: '{label1}' vs '{label2}'")
    if batch_size > 1:
        report_lines.append(f"   NOTE: Data summed in batches of {batch_size}.")
    report_lines.append("="*80)
    
    # The only metric we care about now
    metric = 'sysbench_total_tps'
    
    raw1 = data[label1].get(metric, [])
    raw2 = data[label2].get(metric, [])

    # Filter NaNs
    raw1 = [x for x in raw1 if not np.isnan(x)]
    raw2 = [x for x in raw2 if not np.isnan(x)]

    if not raw1 or not raw2:
        return "No valid TPS data found."

    # Apply Batching
    data1 = np.array(batch_list(raw1, batch_size)).astype(float)
    data2 = np.array(batch_list(raw2, batch_size)).astype(float)

    report_lines.append(f"\n--- Total TPS (Sum of all sub-tests) ---")
    
    if len(data1) < 2 or len(data2) < 2:
        report_lines.append(f"Not enough valid samples for statistics. (Found {len(data1)} vs {len(data2)})")
        report_lines.append(f"Vals1: {data1}")
        report_lines.append(f"Vals2: {data2}")
        return "\n".join(report_lines)
    
    # Stats
    mean1, std1 = np.mean(data1), np.std(data1)
    mean2, std2 = np.mean(data2), np.std(data2)
    
    # Statistical Test (T-test)
    with np.errstate(divide='ignore', invalid='ignore'):
        t_stat, p_value = stats.ttest_ind(data1, data2, equal_var=False, nan_policy='omit')
    
    if np.isnan(p_value): p_value = 1.0

    # Calculate % Diff (Relative to Label 2)
    if mean2 != 0:
        diff_pct = ((mean1 - mean2) / mean2) * 100
    else:
        diff_pct = 0.0

    report_lines.append(f"{'':<25} | {'Mean (Tx/s)':>15} | {'Std Dev':>15} | {'N'}")
    report_lines.append("-"*75)
    report_lines.append(f"{label1:<25} | {mean1:>15.2f} | {std1:>15.2f} | {len(data1)}")
    report_lines.append(f"{label2:<25} | {mean2:>15.2f} | {std2:>15.2f} | {len(data2)}")
    
    report_lines.append(f"\nDiff: {diff_pct:+.2f}%  (p-value = {p_value:.4f})")

    if p_value < 0.05:
        report_lines.append(">> STATISTICALLY SIGNIFICANT difference.")
    else:
        report_lines.append(">> NOT statistically significant.")
        
    report_lines.append("\n" + "="*80)
    
    return "\n".join(report_lines)

def main():
    parser = argparse.ArgumentParser(description="Analyze benchmark results (TPS Only).")
    parser.add_argument("results_dir", help="Path to the top-level benchmark results directory.")
    parser.add_argument("--batch-size", type=int, default=1, help="Number of samples to sum into a single batch.")
    args = parser.parse_args()

    if not os.path.isdir(args.results_dir):
        print(f"Error: Directory not found at '{os.path.abspath(args.results_dir)}'")
        sys.exit(1)
        
    all_benchmark_data = analyze_directory(args.results_dir)
    
    if not all_benchmark_data:
        print("No benchmark data found to analyze.")
        return

    report = print_analysis(all_benchmark_data, args.batch_size)
    print(report)

    analysis_output_path = os.path.join(args.results_dir, f'analysis_batch{args.batch_size}.txt')
    with open(analysis_output_path, 'w') as f:
        f.write(report)
    print(f"📂 Saving report to {analysis_output_path}")

if __name__ == "__main__":
    main()