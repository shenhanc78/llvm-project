from collections import defaultdict
import os
import re
import json

class Parser:
    def __init__(self, directory, validator=None):
        self.directory = directory

        if validator:
            self.validator = validator

    def parse_liveness_files(self):
        """
        Parses all 'ipra_analysis_*.txt' files in a directory to build a model
        of the program's call graph and register usage.
        """
        function_regs = {}
        function_hotness = {} # Store hotness for each function
        function_entrycount = {}
        callee_call_sites = defaultdict(lambda: defaultdict(list))
        # The call graph is represented as Caller -> set(Callees)
        successors = defaultdict(set)
        predecessors = defaultdict(set)
        all_functions = set()

        func_pattern = re.compile(r"IPRA: Function: (.*?)\[")
        usage_pattern = re.compile(r"CallingConv: (\d+) CSRegUsage: (.*?) IsFunctionEntryHot: (\d+) EntryCount: (\d+)")
        call_pattern = re.compile(r"Calls: (.*?)\[.*\] IsTailCall: (\d+).*? LivingCSRegs: (.*)")
        mbb_pattern = re.compile(r"MBB: (\d+)\s+IsMBBHot: (\d+)\s+MBBCount: (\d+)")

        files_to_process = [os.path.join(self.directory, f) for f in os.listdir(self.directory) if f.startswith('ipra_analysis_') and f.endswith('.txt')]
        print(f"Found {len(files_to_process)} profile files to process.")


        for filepath in files_to_process:
            with open(filepath, 'r') as f:
                if os.fstat(f.fileno()).st_size == 0:
                    print(f"WARNING: File {f} is empty, skipping")
                    continue
                for line in f:
                    # Every line must have function name or something is wrong
                    func_match = func_pattern.search(line)
                    if not func_match:
                        breakpoint()
                        raise ValueError(f"Line {line} does not have a function, which is not expected")
                    caller = func_match.group(1).strip()
                    all_functions.add(caller)
                        

                    usage_match = usage_pattern.search(line)
                    if usage_match:
                        calling_convention = int(usage_match.group(1).strip())
                        regs_str = usage_match.group(2).strip()
                        regs_list = regs_str.split() if regs_str else []

                        if hasattr(self, "validator"):
                            self.validator.validate_regs(regs_list, line)

                        function_regs[caller] = set(regs_list)
                        is_hot = (int(usage_match.group(3).strip()) == 1)
                        function_entry_count = int(usage_match.group(4).strip())
                        function_hotness[caller] = is_hot
                        function_entrycount[caller] = function_entry_count
                        
                    
                    mbb_match = mbb_pattern.search(line)
                    if mbb_match:
                        mbb_id = int(mbb_match.group(1))
                        mbb_is_hot = int(mbb_match.group(2))
                        mbb_count = int(mbb_match.group(3))

                    call_match = call_pattern.search(line)
                    if call_match:
                        callee = call_match.group(1).strip()
                        is_tail_call_str = call_match.group(2).strip()
                        
                        all_functions.add(callee)
                        live_regs_str = call_match.group(3).strip()
                        live_regs_list = live_regs_str.split() if live_regs_str else []

                        if hasattr(self, "validator"):
                            self.validator.validate_regs(live_regs_list, line)

                        callee_call_sites[callee][caller].append({
                            "live_csrs": set(live_regs_list),
                            "mbb_count": mbb_count,
                            "is_tail_call": (int(is_tail_call_str) == 1),
                            "is_default_cc": calling_convention == 0,
                            "is_mbb_hot": mbb_is_hot == 1
                        })
                        successors[caller].add(callee)
                        predecessors[callee].add(caller)

        print(f"Found {len(all_functions)} unique functions in the call graph.")
        return function_regs, callee_call_sites, successors, predecessors, all_functions, function_hotness, function_entrycount

    def parse_dangerous_functions(self, bad_function_path=None):
        files_to_process = [os.path.join(self.directory, f) for f in os.listdir(self.directory) if f.startswith('ipra_prera_analysis_') and f.endswith('.txt')]
        # Regex to capture the main components of a line
        main_pattern = re.compile(r"^IPRA: Function: (.+?)\[(.*?)\]\s*(.*)$")
        # Regex to find all flag names within the flags part of the line
        flag_pattern = re.compile(r"(\w+): \d+")
        dangerous_functions = {}
        for filepath in files_to_process:
            with open(filepath, 'r', errors='ignore') as f:
                for line in f:
                    main_match = main_pattern.match(line.strip())
                    
                    if main_match:
                        func_name = main_match.group(1)
                        cu_name = main_match.group(2)
                        flags_string = main_match.group(3)
                        present_flags = flag_pattern.findall(flags_string)
                        
                        dangerous_functions[func_name] = present_flags
        
        dangerous_functions["main"] = ["MAIN"]

        # Filter out known bad functions
        if not bad_function_path:
            print(f"WARNING: BAD_FUNCTION_PATH: {bad_function_path} does not exist")
            print(f"Get {len(dangerous_functions)} dangerous functions.")
            return dangerous_functions

        try:
            with open(bad_function_path, 'r') as file:
                for line in file:
                    bad_func = line.strip()
                    dangerous_functions[bad_func] = ["UNKNOWN"]
        except Exception:
            raise FileNotFoundError(f"ERROR: BAD_FUNCTION_PATH: {bad_function_path} does not exist")

        print(f"Get {len(dangerous_functions)} dangerous functions.")
        return dangerous_functions
    

    def load_pn_context(self):
        pattern = r"^(.+)/liveness_output/(.+)_liveness_output/?$"
        replacement = r"\1/pn_functions/\2_pn_functions"
        context_directory = re.sub(pattern, replacement, self.directory)

        var_names = [
            "costs", "sites", "successors", "predecessors", "all_nodes",
            "function_hotness", "function_entrycount", "dangerous_functions"
        ]

        loaded_data = {}
        print(f"Loading context from: {context_directory}")
        
        for var_name in var_names:
            file_path = os.path.join(context_directory, f"{var_name}.json")
            try:
                with open(file_path, 'r') as f:
                    loaded_data[var_name] = json.load(f)
            except FileNotFoundError:
                print(f"Error: Context file not found {file_path}")
                raise
            except json.JSONDecodeError:
                print(f"Error: Failed to decode JSON from {file_path}")
                raise

        print(f"Successfully loaded {len(loaded_data)} context files.")

        # --- Re-convert data structures ---

        # 1. costs: dict[str, list] -> dict[str, set]
        costs = {func: set(regs) for func, regs in loaded_data['costs'].items()}

        # 2. sites: Rebuild defaultdicts and inner sets
        sites_data = loaded_data['sites']
        sites_dd = defaultdict(lambda: defaultdict(list))
        for callee, callers_dict in sites_data.items():
            # Rebuild inner defaultdict
            sites_dd[callee] = defaultdict(list)
            for caller, call_sites in callers_dict.items():
                # Rebuild inner sets
                for call_site in call_sites:
                    call_site['live_csrs'] = set(call_site['live_csrs'])
                sites_dd[callee][caller] = call_sites

        # 3. successors: dict[str, list] -> defaultdict(set)
        successors_dd = defaultdict(set)
        for caller, callees in loaded_data['successors'].items():
            successors_dd[caller] = set(callees)
            
        # 4. predecessors: dict[str, list] -> defaultdict(set)
        predecessors_dd = defaultdict(set)
        for callee, callers in loaded_data['predecessors'].items():
            predecessors_dd[callee] = set(callers)

        # 5. all_nodes: list -> set
        all_nodes = set(loaded_data['all_nodes'])

        # 6. Others (hotness, entrycount, dangerous) are loaded in the correct format
        
        # Return in the same order as parse_liveness_files, plus dangerous_functions
        return (
            costs,  # This is function_regs
            sites_dd, # This is callee_call_sites
            successors_dd,
            predecessors_dd,
            all_nodes,
            loaded_data['function_hotness'],
            loaded_data['function_entrycount'],
            loaded_data['dangerous_functions']
        )

class TestParser:
    def __init__(self, parser: Parser):
        self.parser = parser

    def test_parse_files(self):
        function_regs, callee_call_sites, successors, predecessors, all_functions, function_hotness, function_entrycount = self.parser.parse_liveness_files()

        expected_all_functions = {
            "_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE",
            "_ZN5clang12Preprocessor3LexERNS_5TokenE",
            "_ZN5clang6Parser35handleUnexpectedCodeCompletionTokenEv",
            "_ZN5clang12Preprocessor9PeekAheadEj",
            "_ZNK5clang19StreamingDiagnostic12AddFixItHintERKNS_9FixItHintE",
            "_ZNK5clang19StreamingDiagnostic9AddStringEN4llvm9StringRefE",
            "_ZN5clang5Lexer11getSpellingB5cxx11ERKNS_5TokenERKNS_13SourceManagerERKNS_11LangOptionsEPb",
            "_ZdlPvm",
            "_ZN5clang6Parser15ConsumeAnyTokenEb",
            "_ZN5clang17DiagnosticBuilderD2Ev",
            "_ZN5clang6Parser16ExpectAndConsumeENS_3tok9TokenKindEjN4llvm9StringRefE",
            "_ZN5clang18SemaCodeCompletion24CodeCompleteOrdinaryNameEPNS_5ScopeENS0_23ParserCompletionContextE",
            "_ZN5clang6Parser16ConsumeExtraSemiENS0_13ExtraSemiKindENS_17TypeSpecifierTypeE",
            "_ZN5clang8DeclSpec16getSpecifierNameENS_17TypeSpecifierTypeERKNS_14PrintingPolicyE",
            "_ZN5clang20DiagStorageAllocator8AllocateEv",
            "_ZN5clang6Parser16expectIdentifierEv",
            "_ZNK5clang14IdentifierInfo18isCPlusPlusKeywordERKNS_11LangOptionsE",
        }
        
        # 2. function_regs
        expected_function_regs = {
            "_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE": {'$rbx', '$r12', '$r13', '$r14', '$r15', '$rbp'},
            "_ZN5clang6Parser35handleUnexpectedCodeCompletionTokenEv": {'$rbx'},
            "_ZN5clang6Parser16ConsumeExtraSemiENS0_13ExtraSemiKindENS_17TypeSpecifierTypeE": {'$rbx', '$r12', '$r13', '$r14', '$r15', '$rbp'},
            "_ZN5clang6Parser16expectIdentifierEv": {'$rbx', '$r14'},
        }
        
        # 3. function_hotness
        expected_function_hotness = {
            "_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE": True,
            "_ZN5clang6Parser35handleUnexpectedCodeCompletionTokenEv": False,
            "_ZN5clang6Parser16ConsumeExtraSemiENS0_13ExtraSemiKindENS_17TypeSpecifierTypeE": False,
            "_ZN5clang6Parser16expectIdentifierEv": False,
        }
        
        # 4. function_entrycount
        expected_function_entrycount = {
            "_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE": 37917718,
            "_ZN5clang6Parser35handleUnexpectedCodeCompletionTokenEv": 0,
            "_ZN5clang6Parser16ConsumeExtraSemiENS0_13ExtraSemiKindENS_17TypeSpecifierTypeE": 42517,
            "_ZN5clang6Parser16expectIdentifierEv": 0,
        }
        
        # 5. successors
        expected_successors = defaultdict(set, {
            '_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE': {
                '_ZNK5clang19StreamingDiagnostic12AddFixItHintERKNS_9FixItHintE',
                '_ZN5clang6Parser16ExpectAndConsumeENS_3tok9TokenKindEjN4llvm9StringRefE',
                '_ZdlPvm', '_ZN5clang12Preprocessor9PeekAheadEj',
                '_ZNK5clang19StreamingDiagnostic9AddStringEN4llvm9StringRefE',
                '_ZN5clang6Parser35handleUnexpectedCodeCompletionTokenEv',
                '_ZN5clang12Preprocessor3LexERNS_5TokenE',
                '_ZN5clang5Lexer11getSpellingB5cxx11ERKNS_5TokenERKNS_13SourceManagerERKNS_11LangOptionsEPb',
                '_ZN5clang6Parser15ConsumeAnyTokenEb',
                '_ZN5clang17DiagnosticBuilderD2Ev'},
            '_ZN5clang6Parser35handleUnexpectedCodeCompletionTokenEv': {
                '_ZN5clang18SemaCodeCompletion24CodeCompleteOrdinaryNameEPNS_5ScopeENS0_23ParserCompletionContextE'},
            '_ZN5clang6Parser16ConsumeExtraSemiENS0_13ExtraSemiKindENS_17TypeSpecifierTypeE': {
                '_ZdlPvm', '_ZNK5clang19StreamingDiagnostic12AddFixItHintERKNS_9FixItHintE',
                '_ZN5clang12Preprocessor3LexERNS_5TokenE',
                '_ZN5clang20DiagStorageAllocator8AllocateEv',
                '_ZN5clang8DeclSpec16getSpecifierNameENS_17TypeSpecifierTypeERKNS_14PrintingPolicyE',
                '_ZN5clang17DiagnosticBuilderD2Ev'},
            '_ZN5clang6Parser16expectIdentifierEv': {
                '_ZNK5clang14IdentifierInfo18isCPlusPlusKeywordERKNS_11LangOptionsE',
                '_ZN5clang20DiagStorageAllocator8AllocateEv',
                '_ZN5clang17DiagnosticBuilderD2Ev'}
        })
        
        # 6. predecessors
        expected_predecessors = defaultdict(set, {
            '_ZN5clang12Preprocessor3LexERNS_5TokenE': {
                '_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE',
                '_ZN5clang6Parser16ConsumeExtraSemiENS0_13ExtraSemiKindENS_17TypeSpecifierTypeE'},
            '_ZN5clang6Parser35handleUnexpectedCodeCompletionTokenEv': {
                '_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE'},
            '_ZN5clang12Preprocessor9PeekAheadEj': {
                '_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE'},
            '_ZNK5clang19StreamingDiagnostic12AddFixItHintERKNS_9FixItHintE': {
                '_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE',
                '_ZN5clang6Parser16ConsumeExtraSemiENS0_13ExtraSemiKindENS_17TypeSpecifierTypeE'},
            '_ZNK5clang19StreamingDiagnostic9AddStringEN4llvm9StringRefE': {
                '_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE'},
            '_ZN5clang5Lexer11getSpellingB5cxx11ERKNS_5TokenERKNS_13SourceManagerERKNS_11LangOptionsEPb': {
                '_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE'},
            '_ZdlPvm': {
                '_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE',
                '_ZN5clang6Parser16ConsumeExtraSemiENS0_13ExtraSemiKindENS_17TypeSpecifierTypeE'},
            '_ZN5clang6Parser15ConsumeAnyTokenEb': {
                '_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE'},
            '_ZN5clang17DiagnosticBuilderD2Ev': {
                '_ZN5clang6Parser16expectIdentifierEv',
                '_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE',
                '_ZN5clang6Parser16ConsumeExtraSemiENS0_13ExtraSemiKindENS_17TypeSpecifierTypeE'},
            '_ZN5clang6Parser16ExpectAndConsumeENS_3tok9TokenKindEjN4llvm9StringRefE': {
                '_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE'},
            '_ZN5clang18SemaCodeCompletion24CodeCompleteOrdinaryNameEPNS_5ScopeENS0_23ParserCompletionContextE': {
                '_ZN5clang6Parser35handleUnexpectedCodeCompletionTokenEv'},
            '_ZN5clang8DeclSpec16getSpecifierNameENS_17TypeSpecifierTypeERKNS_14PrintingPolicyE': {
                '_ZN5clang6Parser16ConsumeExtraSemiENS0_13ExtraSemiKindENS_17TypeSpecifierTypeE'},
            '_ZN5clang20DiagStorageAllocator8AllocateEv': {
                '_ZN5clang6Parser16expectIdentifierEv',
                '_ZN5clang6Parser16ConsumeExtraSemiENS0_13ExtraSemiKindENS_17TypeSpecifierTypeE'},
            '_ZNK5clang14IdentifierInfo18isCPlusPlusKeywordERKNS_11LangOptionsE': {
                '_ZN5clang6Parser16expectIdentifierEv'}
        })
        
        # 7. callee_call_sites
        expected_callee_call_sites = defaultdict(lambda: defaultdict(list), {
            '_ZN5clang12Preprocessor3LexERNS_5TokenE': {
                '_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE': [
                    {'live_csrs': set(), 'mbb_count': 37917718, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': True}
                ],
                '_ZN5clang6Parser16ConsumeExtraSemiENS0_13ExtraSemiKindENS_17TypeSpecifierTypeE': [
                    {'live_csrs': {'$rbx', '$r13', '$r14', '$r15'}, 'mbb_count': 42517, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': False},
                    {'live_csrs': {'$rbx', '$r12', '$r13', '$r14', '$r15'}, 'mbb_count': 0, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': False},
                    {'live_csrs': {'$rbx', '$rbp', '$r12', '$r13', '$r14', '$r15'}, 'mbb_count': 0, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': False}
                ]
            },
            '_ZN5clang6Parser35handleUnexpectedCodeCompletionTokenEv': {
                '_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE': [
                    {'live_csrs': set(), 'mbb_count': 0, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': False}
                ]
            },
            '_ZN5clang12Preprocessor9PeekAheadEj': {
                '_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE': [
                    {'live_csrs': {'$rbx', '$rbp', '$r12', '$r14', '$r15'}, 'mbb_count': 0, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': False}
                ]
            },
            '_ZNK5clang19StreamingDiagnostic12AddFixItHintERKNS_9FixItHintE': {
                '_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE': [
                    {'live_csrs': {'$rbx', '$r12', '$r13', '$r14'}, 'mbb_count': 0, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': False}
                ],
                '_ZN5clang6Parser16ConsumeExtraSemiENS0_13ExtraSemiKindENS_17TypeSpecifierTypeE': [
                    {'live_csrs': {'$rbx', '$r14'}, 'mbb_count': 42517, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': False}
                ]
            },
            '_ZNK5clang19StreamingDiagnostic9AddStringEN4llvm9StringRefE': {
                '_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE': [
                    {'live_csrs': {'$rbx', '$r12', '$r14', '$r15'}, 'mbb_count': 0, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': False}
                ]
            },
            '_ZN5clang5Lexer11getSpellingB5cxx11ERKNS_5TokenERKNS_13SourceManagerERKNS_11LangOptionsEPb': {
                '_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE': [
                    {'live_csrs': {'$rbx', '$r12', '$r14', '$r15'}, 'mbb_count': 0, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': False}
                ]
            },
            '_ZdlPvm': {
                '_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE': [
                    {'live_csrs': {'$rbx', '$r14'}, 'mbb_count': 0, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': False},
                    {'live_csrs': {'$rbx', '$r14'}, 'mbb_count': 0, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': False}
                ],
                '_ZN5clang6Parser16ConsumeExtraSemiENS0_13ExtraSemiKindENS_17TypeSpecifierTypeE': [
                    {'live_csrs': set(), 'mbb_count': 0, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': False}
                ]
            },
            '_ZN5clang6Parser15ConsumeAnyTokenEb': {
                '_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE': [
                    {'live_csrs': {'$rbx', '$r14'}, 'mbb_count': 0, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': False}
                ]
            },
            '_ZN5clang17DiagnosticBuilderD2Ev': {
                '_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE': [
                    {'live_csrs': {'$rbx', '$r14'}, 'mbb_count': 0, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': False}
                ],
                '_ZN5clang6Parser16ConsumeExtraSemiENS0_13ExtraSemiKindENS_17TypeSpecifierTypeE': [
                    {'live_csrs': set(), 'mbb_count': 42517, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': False}
                ],
                '_ZN5clang6Parser16expectIdentifierEv': [
                    {'live_csrs': set(), 'mbb_count': 0, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': False}
                ]
            },
            '_ZN5clang6Parser16ExpectAndConsumeENS_3tok9TokenKindEjN4llvm9StringRefE': {
                '_ZN5clang6Parser20ExpectAndConsumeSemiEjN4llvm9StringRefE': [
                    {'live_csrs': {'$rbx', '$rbp', '$r12', '$r13', '$r14', '$r15'}, 'mbb_count': 0, 'is_tail_call': True, 'is_default_cc': True, 'is_mbb_hot': False}
                ]
            },
            '_ZN5clang18SemaCodeCompletion24CodeCompleteOrdinaryNameEPNS_5ScopeENS0_23ParserCompletionContextE': {
                '_ZN5clang6Parser35handleUnexpectedCodeCompletionTokenEv': [
                    {'live_csrs': {'$rbx'}, 'mbb_count': 0, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': False}
                ]
            },
            '_ZN5clang8DeclSpec16getSpecifierNameENS_17TypeSpecifierTypeERKNS_14PrintingPolicyE': {
                '_ZN5clang6Parser16ConsumeExtraSemiENS0_13ExtraSemiKindENS_17TypeSpecifierTypeE': [
                    {'live_csrs': {'$r12', '$r13', '$r15'}, 'mbb_count': 0, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': False}
                ]
            },
            '_ZN5clang20DiagStorageAllocator8AllocateEv': {
                '_ZN5clang6Parser16ConsumeExtraSemiENS0_13ExtraSemiKindENS_17TypeSpecifierTypeE': [
                    {'live_csrs': {'$rbx', '$r12', '$r13', '$r14', '$r15'}, 'mbb_count': 0, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': False},
                    {'live_csrs': {'$rbx', '$r12', '$r13'}, 'mbb_count': 0, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': False}
                ],
                '_ZN5clang6Parser16expectIdentifierEv': [
                    {'live_csrs': {'$rbx'}, 'mbb_count': 0, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': False},
                    {'live_csrs': {'$rbx', '$r14'}, 'mbb_count': 0, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': False}
                ]
            },
            '_ZNK5clang14IdentifierInfo18isCPlusPlusKeywordERKNS_11LangOptionsE': {
                '_ZN5clang6Parser16expectIdentifierEv': [
                    {'live_csrs': {'$rbx'}, 'mbb_count': 0, 'is_tail_call': False, 'is_default_cc': True, 'is_mbb_hot': False}
                ]
            }
        })

        assert(function_regs == expected_function_regs)
        assert(callee_call_sites == expected_callee_call_sites)
        assert(successors == expected_successors)
        assert(predecessors == expected_predecessors)
        assert(all_functions == expected_all_functions)
        assert(function_hotness == expected_function_hotness)
        assert(function_entrycount == expected_function_entrycount)

        print("parse_files test case pass.")