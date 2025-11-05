import json

FUNCTION_DATA = "../metrics/pn_functions/thinlto_autofdo_pn_functions/liveness_profdata.json"
ACTUAL_USAGE_DATA = "../../../ipra-run/pn_thinlto_autofdo_clang/pn_functions.txt"

with open(FUNCTION_DATA, 'r') as f:
    function_dict = json.load(f)["functions"]

actual_usage_set = set()
with open(ACTUAL_USAGE_DATA, 'r') as f:
    for func_name in f:
        actual_usage_set.add(func_name.strip())

theoretical_dynamic_scores = sum(function_dict.values())
actual_dynamic_score = sum([score for func, score in function_dict.items() if func in actual_usage_set])

print("=" * 20)
print(f"Theoretical Dynamic Score: {theoretical_dynamic_scores}")
print(f"Actual Dynamic Score: {actual_dynamic_score}")
print(f"Theoretical Funtion Length: {len(function_dict)}")
print(f"Actual Function Length: {len(actual_usage_set)}")
print("=" * 20)

# mismatched_functions = {func for func, _ in function_dict.items() if func not in actual_usage_set}
# print(f"Mismatched functions: {mismatched_functions}")
# with open("unutilized_functions.json", "w") as f:
#     data = {func: score for func, score in function_dict.items() if func not in actual_usage_set}
#     json.dump(data, f)

