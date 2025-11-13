import cxxfilt
from .graph_algorithms import GraphAlgorithm
import copy
import re
from collections import defaultdict

class Scoring:
    def __init__(self, function_regs, callee_call_sites, successors, predecessors,
                    all_functions, function_hotness, function_entrycount, dangerous_functions, good_functions=None,
                    skip_scc=False, skip_cold=True, skip_cold_edge=False, skip_tail=False, skip_scoring=False,
                    allow_cdtor=None, skip_propagate=False, good_functions_only=False, callee_register_threshold=0, static_threshold=0, dynamic_threshold=0):
            self.function_regs = function_regs
            self.callee_call_sites = callee_call_sites
            self.successors = successors
            self.predecessors = predecessors
            self.all_functions = all_functions
            self.function_hotness = function_hotness
            self.function_entrycount = function_entrycount
            self.dangerous_functions = dangerous_functions
            self.good_functions = good_functions
            self.skip_scc = skip_scc
            self.skip_cold = skip_cold
            self.skip_cold_edge = skip_cold_edge
            self.skip_tail = skip_tail
            self.skip_scoring = skip_scoring
            self.allow_cdtor = allow_cdtor if allow_cdtor is not None else set()
            self.skip_propagate = skip_propagate
            self.good_functions_only=good_functions_only
            self.callee_register_threshold = callee_register_threshold
            self.static_threshold = static_threshold
            self.dynamic_threshold = dynamic_threshold

    def calculate_benefits(self, show_message=False):
            # Copy to avoid changing the original function_regs
            # This is beneficial to avoid loading function_regs repeatedly to test different algorithms
            function_regs = copy.deepcopy(self.function_regs)

            if self.callee_register_threshold > 6 or self.callee_register_threshold < 0:
                raise ValueError(f"callee_register_threshold={self.callee_register_threshold} not in expected range [0, 6]")
            
            
            """
            Calculates benefit scores using a bottom-up traversal of the call graph
            to model the cascading effects of the preserve_none optimization.
            ... [docstring unchanged] ...
            """
            report_string = ""
            report_string += "=" * 20 + "\n"
            report_string += f"Algorithm runned with:\n\tskip_scc={self.skip_scc}\n\tskip_cold={self.skip_cold}\n\tskip_cold_edge={self.skip_cold_edge}\n"
            report_string += f"\tskip_tail={self.skip_tail}\n\tallow_cdtor={self.allow_cdtor}\n\tgood_functions_only={self.good_functions_only}\n"
            report_string += f"\tstatic_threshold={self.static_threshold}\n\tdynamic_threshold={self.dynamic_threshold}\n"
            report_string += f"\tcallee_register_threshold={self.callee_register_threshold}\n\tskip_scoring={self.skip_scoring}\n\tskip_propagate={self.skip_propagate}\n"

            res = GraphAlgorithm.function_order_bottom_up(self.all_functions, self.successors, self.predecessors)
            sorted_nodes = res["flat_functions_bottom_up"]
            report_string += "-" * 10 + "\n"
            report_string += f"Topologically sorted {len(sorted_nodes)} functions for bottom-up processing.\n"
            report_string += "-" * 10 + "\n"

            final_scores = {}

            if self.skip_scc:
                sccs = res["sccs"]
                functions_in_cycles = set()
                for scc in sccs:
                    if len(scc) > 1:
                        for func_in_cycle in scc:
                            functions_in_cycles.add(func_in_cycle)
                report_string += "-" * 10 + "\n"
                report_string += f"Identified {len(functions_in_cycles)} functions in recursive cycles.\n"

            dangerous_function_count = 0 # For record only
            ctor_dtor_count = 0          # <-- Added counter for ctor/dtor
            clone_count = 0
            clone_pattern = re.compile(r'\.llvm\.\d+$')

            for callee in sorted_nodes:
                # ... [clone logic unchanged] ...
                if clone_pattern.search(callee):
                    clone_count += 1
                    self.dangerous_functions[callee] = self.dangerous_functions.get(callee, []) + ["CLONE"]
                    continue
                # ... [good_functions_only logic unchanged] ...
                if self.good_functions_only and callee not in self.good_functions:
                    self.dangerous_functions[callee] = self.dangerous_functions.get(callee, []) + ["NOTGOOD"]
                    continue

                # Step 1: Use demangled name to check if it's a ctor/dtor at all.
                try:
                    demangled_name = cxxfilt.demangle(callee)
                except cxxfilt.InvalidName:
                    demangled_name = callee 
                
                is_ctor_or_dtor = False
                if '::' in demangled_name: # Check if it's likely a method
                    parts = demangled_name.split('::')
                    if len(parts) >= 2:
                        class_name_part = parts[-2]
                        method_name_part = parts[-1]
            
                        # Get base class name, stripping templates (e.g., "MyClass<int>" -> "MyClass")
                        base_class_name = re.sub(r'<.*>', '', class_name_part).strip()
                        
                        # Get base method name, stripping arguments (e.g., "MyClass(int)" -> "MyClass")
                        base_method_name = re.sub(r'\(.*\)', '', method_name_part).strip()
            
                        # Constructor check: e.g., MyClass::MyClass
                        if base_method_name == base_class_name:
                            is_ctor_or_dtor = True
                        
                        # Destructor check: e.g., MyClass::~MyClass
                        elif base_method_name == '~' + base_class_name:
                            is_ctor_or_dtor = True

                # Step 2: If it IS a ctor/dtor, find its specific type and check against the allow list.
                if is_ctor_or_dtor:
                    # This regex finds C1, C2, D1, or D2 if they are followed by
                    # a capital letter (start of a type) or 'Ev' (void).
                    cdtor_token_match = re.search(r"(C[12]|D[12])([A-Z]|Ev$)", callee)

                    cdtor_type = None
                    if cdtor_token_match:
                        cdtor_type = cdtor_token_match.group(1) # "C1", "C2", "D1", or "D2"

                    # Check if the found type is allowed.
                    # If it's not C1/C2/D1/D2 (cdtor_type is None) or it's not in the set, skip it.
                    if cdtor_type not in self.allow_cdtor:
                        ctor_dtor_count += 1
                        # Add a more informative tag, e.g., "CDTOR_C1" or "CDTOR_OTHER"
                        tag = f"CDTOR_{cdtor_type}" if cdtor_type else "CDTOR_OTHER"
                        self.dangerous_functions[callee] = self.dangerous_functions.get(callee, []) + [tag]
                        continue

                call_sites = self.callee_call_sites.get(callee, defaultdict(list))
                # (Optional) Skip Tail Calls
                if self.skip_tail:
                    is_tail_call = False
                    for caller, sites in call_sites.items():
                        is_tail_call = any([site["is_tail_call"] for site in sites])
                        if is_tail_call:
                            break
                    if is_tail_call:
                        self.dangerous_functions[callee] = self.dangerous_functions.get(callee, []) + ["TAILCALL"]
                        continue

                # (Optional) Skip any function that is part of a recursive cycle.
                if self.skip_scc and callee in functions_in_cycles:
                    self.dangerous_functions[callee] = self.dangerous_functions.get(callee, []) + ["SCC"]
                    continue

                # (Optional) Skip any cold function:
                if self.skip_cold and self.function_hotness.get(callee, False) == False:
                    self.dangerous_functions[callee] = self.dangerous_functions.get(callee, []) + ["COLD"]
                    continue

                if len(function_regs.get(callee, [])) < self.callee_register_threshold:
                    self.dangerous_functions[callee] = self.dangerous_functions.get(callee, []) + [f"NUMREG"]
                    continue
                
            for callee in sorted_nodes:
                if callee in self.dangerous_functions:
                    dangerous_function_count += 1
                    continue

                callee_regs_set = function_regs.get(callee, {})
                callee_cost = len(callee_regs_set)

                # TODO: Propagation will double count callee_cost, need to discount to avoid inflating scores
                # TODO: live register push/pop instruction count might by overestimated if the reigster is live but not used between two consecutive call sites
                total_dynamic_benefit = 2 * callee_cost * self.function_entrycount.get(callee, 0)
                total_static_cost = 2 * (-callee_cost)
                call_sites = self.callee_call_sites.get(callee, defaultdict(list))
                for caller, sites in call_sites.items():
                    if self.skip_cold_edge and self.function_hotness[caller] == False: #skip cold edge cost in our cost model
                        continue
                    caller_entry_count = self.function_entrycount[caller]
                    # If caller and callee are the same, prologue/epilogue costs (both static/dynamic) are not applicable
                    if caller != callee:
                        # prologue/epilogue cost/benefit analysis
                        caller_prologue_cost = 6 - len(function_regs.get(caller, {}))
                        total_dynamic_benefit -= 2 * caller_prologue_cost * caller_entry_count
                        total_static_cost += 2 * caller_prologue_cost
                    # live around callsite cost/benefit analysis
                    for site in sites:
                        mbb_count = site["mbb_count"]
                        caller_live_regs_cost = len(site["live_csrs"].intersection(callee_regs_set))
                        total_dynamic_benefit -= 2 * caller_live_regs_cost * mbb_count
                        total_static_cost += 2 * caller_live_regs_cost

                if self.skip_scoring or (total_dynamic_benefit > self.dynamic_threshold and total_static_cost < self.static_threshold):
                    final_scores[callee] = {"dynamic": total_dynamic_benefit, "static": total_static_cost}

                    # Taking effect of PreserveNone
                    if not self.skip_propagate:
                        function_regs[callee] = {}
                        for caller in self.predecessors[callee]:
                            # TODO: to be more precise, we have to know whether register allocator uses rbp or not
                            if caller != callee: #Skip propagation when caller and callee are the same
                                function_regs[caller] = {"$rbx", "$rbp", "$r12", "$r13", "$r14", "$r15"}

            report_string += "*" * 10 + "\n"
            report_string += f"Filtered {dangerous_function_count} dangerous functions.\n"
            report_string += f"Filtered {ctor_dtor_count} constructors/destructors.\n"
            report_string += f"Filtered {clone_count} cloned functions.\n"
            report_string += f"Found {len(final_scores)} function candidates.\n"
            report_string += "*" * 10 + "\n"
            report_string += "=" * 20 + "\n"

            if show_message:
                return final_scores, report_string

            return final_scores