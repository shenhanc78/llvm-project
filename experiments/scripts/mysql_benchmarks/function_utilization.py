import json
import os
import sys

# ------- Configuration for MySQL Experiment --------
# This is the build we are analyzing (the one that *uses* the profile)
TARGET_BUILD = 'pn_thinlto_autofdo_mysql'

# This is the build we analyzed to *generate* the profile
PROFILE_SOURCE_BUILD = 'thinlto_autofdo_mysql'

# --- Paths relative to mysql_benchmarks/ ---

# Path to the JSON file we fed *into* the compiler
FUNCTION_DATA = f"../../metrics/pn_functions/{PROFILE_SOURCE_BUILD}_pn_functions/liveness_profdata.json"

# Path to the .txt file the compiler *generated*
ACTUAL_USAGE_DATA = f"../../../../ipra-run/mysql_benchmark/{TARGET_BUILD}/pn_functions.txt"

# --- End Configuration ---

print(f"Comparing theoretical vs. actual function usage for '{TARGET_BUILD}'")
print(f"  Theoretical profile: {FUNCTION_DATA}")
print(f"  Actual usage log:    {ACTUAL_USAGE_DATA}")

try:
    with open(FUNCTION_DATA, 'r') as f:
        function_dict = json.load(f)["functions"]
except FileNotFoundError:
    print(f"\n[ERROR] Cannot find theoretical profile: {FUNCTION_DATA}")
    print("Please run 'generate_liveness_profdata.py' first.")
    sys.exit(1)
except (json.JSONDecodeError, KeyError):
    print(f"\n[ERROR] Failed to parse JSON from {FUNCTION_DATA}.")
    print("Make sure it is a valid JSON file with a 'functions' key.")
    sys.exit(1)

actual_usage_set = set()
try:
    with open(ACTUAL_USAGE_DATA, 'r') as f:
        for func_name in f:
            actual_usage_set.add(func_name.strip())
except FileNotFoundError:
    print(f"\n[ERROR] Cannot find actual usage log: {ACTUAL_USAGE_DATA}")
    print(f"Did the '{TARGET_BUILD}' build fail? Or did you forget to 'make clean'?")
    sys.exit(1)

if not function_dict:
    print("\n[Warning] The theoretical function list is empty. No analysis to perform.")
    sys.exit(0)

theoretical_dynamic_scores = sum(function_dict.values())
actual_dynamic_score = sum([score for func, score in function_dict.items() if func in actual_usage_set])

print("=" * 20)
print(f"Theoretical Dynamic Score: {theoretical_dynamic_scores:,.2f}")
print(f"Actual Dynamic Score: {actual_dynamic_score:,.2f}")
print(f"Score Utilization: {actual_dynamic_score / theoretical_dynamic_scores * 100:.2f}%")
print("-" * 20)
print(f"Theoretical Funtion Count: {len(function_dict)}")
print(f"Actual Function Count: {len(actual_usage_set)}")
print(f"Function Utilization: {len(actual_usage_set) / len(function_dict) * 100:.2f}%")
print("=" * 20)

# Find functions we *wanted* to modify but the compiler *didn't*
unutilized_functions = {func: score for func, score in function_dict.items() if func not in actual_usage_set}
if unutilized_functions:
    print(f"Found {len(unutilized_functions)} unutilized functions (in profile but not in output):")
    # Sort by score, descending
    sorted_unutilized = sorted(unutilized_functions.items(), key=lambda item: item[1], reverse=True)
    for func, score in sorted_unutilized[:10]: # Print top 10
        print(f"  - {func} (Score: {score:,.2f})")
    if len(unutilized_functions) > 10:
        print(f"  ... and {len(unutilized_functions) - 10} more.")
else:
    print("✅ All functions in the profile were utilized.")

# Find functions the compiler *did* modify but we *didn't* ask for (should be 0)
extra_functions = {func for func in actual_usage_set if func not in function_dict}
if extra_functions:
    print(f"\n[WARNING] Found {len(extra_functions)} extra functions (in output but not in profile):")
    for func in list(extra_functions)[:10]:
        print(f"  - {func}")
else:
    print("✅ No extra functions were utilized.")