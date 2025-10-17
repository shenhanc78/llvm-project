import json

FUNCTION_DATA = "../metrics/thinly_linked_fdo_liveness_output/liveness_profdata.json"
ACTUAL_USAGE_DATA = "../../../ipra-run/preserve_none_thinly_linked_fdo_clang/pn_functions.txt"

with open(FUNCTION_DATA, 'r') as f:
    function_dict = json.load(f)["functions"]

actual_usage_set = set()
with open(ACTUAL_USAGE_DATA, 'r') as f:
    for func_name in f:
        actual_usage_set.add(func_name)

theoretical_dynamic_scores = sum(function_dict.values())
actual_dynamic_score = sum([score for func, score in function_dict.items() if func in actual_usage_set])

print("=" * 20)
print(f"Theoretical Dynamic Score: {theoretical_dynamic_scores}")
print(f"Actual Dynamic Score: {actual_dynamic_score}")
print("=" * 20)


