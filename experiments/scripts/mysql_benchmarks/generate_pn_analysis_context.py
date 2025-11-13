import os
import json
import sys
# Assumes the 'lib' folder is in the parent directory (scripts/)
sys.path.append('../../')
from lib.pylib.graph_algorithms import GraphAlgorithm
from lib.pylib.validators import Validator
from lib.pylib.parsers import Parser, TestParser
from lib.pylib.utils import Util
from lib.pylib.scoring import Scoring

# ------- Configuration for MySQL Experiment --------
# This should be the name of the target build you are analyzing
TARGET = 'thinlto_autofdo_mysql'

# ------- Constants determined by `target` ---------
# Paths are now relative to the mysql_benchmarks/ directory
LIVENESS_DIR = f'../../metrics/liveness_output/{TARGET}_liveness_output/'
CONTEXT_OUTPUT_DIR = f'../../metrics/pn_functions/{TARGET}_pn_functions/'
BAD_FUNCTION_PATH = '../../metrics/pn_functions/mysql_bad_functions.txt'

print(f"TARGET: {TARGET}")
print(f"LIVENESS_DIR: {LIVENESS_DIR}")
print(f"CONTEXT_OUTPUT_DIR: {CONTEXT_OUTPUT_DIR}")
print(f"BAD_FUNCTION_PATH: {BAD_FUNCTION_PATH}")

validator = Validator(system_arch="x86-64", abi="System V")
parser = Parser(LIVENESS_DIR, validator)
# test_parser = TestParser(Parser('../tests/ipra_analysis_test_dir', validator))
# test_parser.test_parse_files()

costs, sites, successors, predecessors, all_nodes, function_hotness, function_entrycount = parser.parse_liveness_files()
dangerous_functions = parser.parse_dangerous_functions(BAD_FUNCTION_PATH)

# Serialization effort to .json
costs = {function: list(reg_set) for function, reg_set in costs.items()}
for callee, callers_dict in sites.items():
    for caller, call_sites in callers_dict.items():
        for call_site in call_sites:
            call_site['live_csrs'] = list(call_site['live_csrs'])
all_nodes = list(all_nodes)
successors = {key: list(value) for key, value in successors.items()}
predecessors = {key: list(value) for key, value in predecessors.items()}

data_to_save = {
        "costs": costs,
        "sites": sites,
        "successors": successors,
        "predecessors": predecessors,
        "all_nodes": all_nodes,
        "function_hotness": function_hotness,
        "function_entrycount": function_entrycount,
        "dangerous_functions": dangerous_functions
}

os.makedirs(CONTEXT_OUTPUT_DIR, exist_ok=True)
for variable, value in data_to_save.items():
    with open(f"{CONTEXT_OUTPUT_DIR}{variable}.json", "w") as f:
        json.dump(value, f, indent=4)

print(f"✅ Successfully generated context files in '{CONTEXT_OUTPUT_DIR}'")