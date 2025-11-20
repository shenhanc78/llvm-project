from collections import defaultdict, deque
import os
import re
import json
import copy
import argparse
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

# ------- Constants determined by `TARGET` ---------
# Paths are now relative to the mysql_benchmarks/ directory
PN_FUNCTIONS_DIR = f'../../metrics/pn_functions'
LIVENESS_DIR = f'../../metrics/liveness_output/{TARGET}_liveness_output/'
OUTPUT_FILE = f'../../metrics/pn_functions/{TARGET}_pn_functions/liveness_profdata.json'

# ------- Load Context Data for PN Analysis ----------
validator = Validator(system_arch="x86-64", abi="System V")
# The Parser class likely infers the context path from the liveness path
parser = Parser(LIVENESS_DIR, validator)
costs, sites, successors, predecessors, all_nodes, function_hotness, function_entrycount, dangerous_functions = parser.load_pn_context()

# NOTE: You may need to create this 'good_functions.json' file manually
# or adjust this logic if it's not part of your MySQL workflow.
GOOD_FUNCTIONS_FILE = f"{PN_FUNCTIONS_DIR}/mysql_good_functions.json"
if os.path.exists(GOOD_FUNCTIONS_FILE):
    with open(GOOD_FUNCTIONS_FILE, "r") as f:
        good_functions = json.load(f)
        good_functions = set(good_functions['functions'])
else:
    print(f"Warning: '{GOOD_FUNCTIONS_FILE}' not found. Proceeding without a good_functions list.")
    good_functions = None # Or set(all_nodes) if you want to allow all

# ****************************************************************************************************************************************************************************
# ****************************************************************************************************************************************************************************
# ****************************************************************************************************************************************************************************
# ------- Run PN Analysis Algorithm --------
scoring = Scoring(costs, sites, successors, predecessors, 
                  all_nodes, function_hotness, function_entrycount, dangerous_functions, good_functions=good_functions,
                  skip_scc=False, skip_tail=True, skip_cold=True, skip_cold_edge=False, 
                  allow_cdtor={}, skip_propagate=False, good_functions_only=False,
                  static_threshold=0, dynamic_threshold=10, callee_register_threshold=0, skip_scoring=False)
function_dict, scoring_message = scoring.calculate_benefits(show_message=True)
print(scoring_message)
Util.print_scores(function_dict)
# ****************************************************************************************************************************************************************************
# ****************************************************************************************************************************************************************************
# ****************************************************************************************************************************************************************************

# --------- Constructing Dict and Save as JSON -----------
output_dict = {"reference": scoring_message,
               "functions": {func: scores["dynamic"] for func, scores in function_dict.items()}}

with open(OUTPUT_FILE, 'w') as f:
    json.dump(output_dict, f, indent=2)
print(f"✅ Successfully merged profile data into '{OUTPUT_FILE}'")