import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

# --- Import User's Libraries ---
# (Assumes this script is in the same directory as the example)
sys.path.append('../')
from lib.pylib.validators import Validator
from lib.pylib.parsers import Parser
# -----------------------------

# --- CONFIGURATION ---
# (Edit these paths and names before running)

# Path to the first liveness_profdata.json file (e.g., 'Set A').
FILE_A = "../metrics/references/clangbench_results/clangbench_results_2025-11-03_15-06-07/liveness_profdata.json"
NAME_A = "Set_1"

# Path to the second liveness_profdata.json file (e.g., 'Set B').
FILE_B = "../metrics/references/clangbench_results/clangbench_results_2025-11-04_15-42-29/liveness_profdata.json"
NAME_B = "Set_2"

# Path to the directory containing the liveness context data (ipra_analysis_... files).
LIVENESS_DIR = "../metrics/liveness_output/thinlto_autofdo_liveness_output/"

# -----------------------------


def load_pn_set_from_json(json_file):
    """Loads a set of function names from a liveness_profdata.json file."""
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
            # Handles both {"functions": {"name": score}} and {"functions": ["name"]}
            functions_data = data.get("functions", {})
            if isinstance(functions_data, dict):
                return set(functions_data.keys())
            elif isinstance(functions_data, list):
                return set(functions_data)
            else:
                print(f"Error: Unknown 'functions' format in {json_file}")
                return set()
    except FileNotFoundError:
        print(f"Error: File not found at {json_file}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Could not decode JSON from {json_file}")
        sys.exit(1)

def calculate_set_impact(pn_set, function_regs, callee_call_sites, function_hotness, function_entrycount, skip_cold_callers=True):
    """
    Calculates the total cost (in dynamic instructions) and impact
    (affected callers/sites) for a given set of preserve_none functions.
    """
    affected_callers = set()
    affected_call_sites = 0
    total_dynamic_spill_cost = 0
    total_dynamic_save_restore_cost = 0

    for callee in pn_set:
        callee_regs_set = function_regs.get(callee, set())
        if not callee_regs_set:
            continue  # This function didn't save registers anyway

        call_sites_for_callee = callee_call_sites.get(callee, {})
        
        for caller, sites in call_sites_for_callee.items():
            # Optionally skip penalizing calls from cold callers
            if skip_cold_callers and not function_hotness.get(caller, False):
                continue

            is_caller_affected_by_this_callee = False

            for site in sites:
                live_regs = site["live_csrs"].intersection(callee_regs_set)
                live_reg_count = len(live_regs)
                
                affected = False
                if live_reg_count > 0:
                    affected = True
                    total_dynamic_spill_cost += 2 * live_reg_count 
                    is_caller_affected_by_this_callee = True
                if caller not in pn_set and len(function_regs.get(caller, {})) < 6:
                    affected = True
                    total_dynamic_save_restore_cost += 2 * (6 - len(function_regs.get(caller, {}))) 
                    is_caller_affected_by_this_callee = True
                if affected:
                    affected_call_sites += 1
            
            if is_caller_affected_by_this_callee:
                affected_callers.add(caller)

    return {
        "affected_callers": len(affected_callers),
        "affected_call_sites": affected_call_sites,
        "dynamic_spill_cost": total_dynamic_spill_cost,
        "save_restore_cost": total_dynamic_save_restore_cost,
    }

def main():
    # --- 1. Load Context Data ---
    print(f"Loading liveness context from: {LIVENESS_DIR} ...")
    liveness_dir_path = Path(LIVENESS_DIR)
    if not liveness_dir_path.is_dir():
        print(f"Error: Liveness directory not found at '{LIVENESS_DIR}'")
        sys.exit(1)
        
    validator = Validator(system_arch="x86-64", abi="System V")
    context_parser = Parser(str(liveness_dir_path), validator)
    
    # This loads everything:
    # function_regs: The registers each callee saves (our "benefit")
    # callee_call_sites: All call sites and their live registers (our "cost")
    # ... and other context we need.
    function_regs, callee_call_sites, successors, predecessors, all_nodes, \
    function_hotness, function_entrycount, dangerous_functions = context_parser.load_pn_context()
    
    print("✅ Context loaded.")

    # --- 2. Load PN Function Sets ---
    print(f"Loading {NAME_A} from: {FILE_A}")
    set_a = load_pn_set_from_json(FILE_A)
    print(f"Loading {NAME_B} from: {FILE_B}")
    set_b = load_pn_set_from_json(FILE_B)
    print("✅ Function sets loaded.")

    # --- 3. Calculate Impact ---
    print("\nCalculating impact (skipping calls from cold callers)...")
    impact_a = calculate_set_impact(set_a, function_regs, callee_call_sites, function_hotness, function_entrycount, skip_cold_callers=True)
    impact_b = calculate_set_impact(set_b, function_regs, callee_call_sites, function_hotness, function_entrycount, skip_cold_callers=True)

    # --- 4. Report Differences ---
    
    # Set differences
    only_in_a = set_a - set_b
    only_in_b = set_b - set_a
    in_common = set_a & set_b

    # Calculate impact *just* for the changed functions
    impact_only_a = calculate_set_impact(only_in_a, function_regs, callee_call_sites, function_hotness, function_entrycount, skip_cold_callers=True)
    impact_only_b = calculate_set_impact(only_in_b, function_regs, callee_call_sites, function_hotness, function_entrycount, skip_cold_callers=True)

    print("\n" + "="*80)
    print(f"Comparison Report: '{NAME_A}' vs. '{NAME_B}'")
    print("="*80)

    print("\n--- Function Set Differences ---")
    print(f"Total Functions in {NAME_A}: {len(set_a)}")
    print(f"Total Functions in {NAME_B}: {len(set_b)}")
    print(f"Functions in Common:      {len(in_common)}")
    print(f"Functions ONLY in {NAME_A}: {len(only_in_a)}")
    print(f"Functions ONLY in {NAME_B}: {len(only_in_b)}")

    print(f"\n--- Total Impact (Hot Callers Only) ---")
    print(f"{'Metric':<25} | {NAME_A:>20} | {NAME_B:>20} | {'Change (B - A)':>20}")
    print("-"*88)
    
    def print_row(metric, key):
        val_a = impact_a[key]
        val_b = impact_b[key]
        change = val_b - val_a
        print(f"{metric:<25} | {val_a:>20,d} | {val_b:>20,d} | {change:>+20,d}")

    print_row("Affected Callers", "affected_callers")
    print_row("Affected Call Sites", "affected_call_sites")
    print_row("Dynamic Spill Cost (Instr)", "dynamic_spill_cost")
    print_row("Save Restore Cost (Instr)", "save_restore_cost")

    print(f"\n--- Impact of *Changed* Functions (Hot Callers Only) ---")
    print(f"{'Metric':<25} | {'Impact of ' + NAME_A + ' Only':>25} | {'Impact of ' + NAME_B + ' Only':>25}")
    print("-"*88)
    
    def print_delta_row(metric, key):
        val_a = impact_only_a[key]
        val_b = impact_only_b[key]
        print(f"{metric:<25} | {val_a:>25,d} | {val_b:>25,d}")

    print_delta_row("Affected Callers", "affected_callers")
    print_delta_row("Affected Call Sites", "affected_call_sites")
    print_delta_row("Dynamic Spill Cost (Instr)", "dynamic_spill_cost")
    print_delta_row("Save Restore Cost (Instr)", "save_restore_cost")
    
    print("\n" + "="*80)

if __name__ == "__main__":
    main()