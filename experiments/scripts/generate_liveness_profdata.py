from collections import defaultdict, deque
import os
import re
import json
import copy
import argparse
import sys
sys.path.append('../')
from lib.pylib.graph_algorithms import GraphAlgorithm
from lib.pylib.validators import Validator
from lib.pylib.parsers import Parser, TestParser
from lib.pylib.utils import Util
from lib.pylib.scoring import Scoring

# Naive Pair Selection with No Propagation
# cost = { "funcA" : {"r13", "rbp"}
# remove cold call edges
# interleaving calls

COMPILER = 'thinlto_autofdo_clang'

# ------- Constants determined by `COMPILER` ---------
COMPILER_TYPE = COMPILER[:-6]
LIVENESS_DIR = f'../metrics/liveness_output/{COMPILER_TYPE}_liveness_output/'
OUTPUT_FILE = f'../metrics/pn_functions/{COMPILER_TYPE}_pn_functions/liveness_profdata.json'

# ------- Load Context Data for PN Analysis ----------
validator = Validator(system_arch="x86-64", abi="System V")
parser = Parser(LIVENESS_DIR, validator)
costs, sites, successors, predecessors, all_nodes, function_hotness, function_entrycount, dangerous_functions = parser.load_pn_context()

# ****************************************************************************************************************************************************************************
# ****************************************************************************************************************************************************************************
# ****************************************************************************************************************************************************************************
# ------- Run PN Analysis Algorithm --------
scoring = Scoring(costs, sites, successors, predecessors, 
            all_nodes, function_hotness, function_entrycount, dangerous_functions, 
            skip_scc=False, skip_tail=True, skip_cold=True, skip_cold_edge=False, skip_propagate=False,
            static_threshold=0, dynamic_threshold=0, callee_register_threshold=0, skip_scoring=True)
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

# # For pn.syms
# function_names = list(function_dict.keys())
# PN_SYMS_OUTPUT_PATH = f'{LIVENESS_DIR}pn.syms'
# with open(PN_SYMS_OUTPUT_PATH, 'w') as f:
#     for name in function_names:
#         f.write(name + '\n')
# print(f"✅ Successfully created '{PN_SYMS_OUTPUT_PATH}' with {len(function_names)} function symbols.")