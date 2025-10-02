# bisect.py (Iterative, More Robust Version)
import os
import subprocess
import json
import sys
import shutil

# --- Configuration ---
LIVENESS_DATA_DIR = '../metrics/thinly_linked_fdo_liveness_output'
CANDIDATES_JSON = os.path.join(LIVENESS_DATA_DIR, 'liveness_profdata.json')
MAKE_TARGET = 'test_preserve_none_thinly_linked_fdo_clang'
GOOD_FUNCTIONS_JSON = os.path.join(LIVENESS_DATA_DIR, 'good_functions.json')
BAD_FUNCTIONS_TXT = os.path.join(LIVENESS_DATA_DIR, 'bad_functions.txt')

# --- Global State ---
original_candidates_backup = ""
good_functions = set()
bad_functions = set()

def run_make_test(current_test_set):
    """Writes the JSON and runs the make target. Returns True on success."""
    # The pass expects a score, but it's not used, so we use 1.
    data = {"functions": {func: 1 for func in current_test_set}}
    with open(CANDIDATES_JSON, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"\n--- Testing a set of {len(current_test_set)} functions... ---")
    command = f"make {MAKE_TARGET}"
    try:
        subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print("✅ Build and Benchmark SUCCEEDED.")
        return True
    except subprocess.CalledProcessError as e:
        print("❌ Build and Benchmark FAILED. See compiler output below:")
        print("==================== STDOUT ====================")
        print(e.stdout)
        print("==================== STDERR ====================")
        print(e.stderr)
        print("==============================================")
        return False

def find_one_bad_function(candidates):
    """
    Takes a list of candidates that is known to contain at least one failure.
    Narrows it down until exactly one failing function is found.
    """
    pool = list(candidates)
    while len(pool) > 1:
        mid = len(pool) // 2
        first_half = pool[:mid]
        print(f"--> Bisecting failing set of {len(pool)}. Trying first half ({len(first_half)} functions).")
        
        # Test the first half combined with all known good functions
        if run_make_test(good_functions.union(first_half)):
            # The first half is good, so the failure must be in the second half.
            print(f"--> First half SUCCEEDED. Failure is in the second half.")
            pool = pool[mid:]
        else:
            # The first half failed, so the failure is in this half.
            print(f"--> First half FAILED. Focusing on this subset.")
            pool = first_half
            
    # The pool is now size 1, containing the isolated bad function.
    return pool[0]

def write_json_candidates(functions, path):
    """Writes a set of functions to the JSON format."""
    data = {"functions": {func: 1 for func in functions}}
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)

def main():
    global good_functions, bad_functions, original_candidates_backup

    # --- Setup and Restore ---
    backup_path = CANDIDATES_JSON + ".bak"
    if not os.path.exists(backup_path):
        print(f"Backing up original candidates file to {backup_path}")
        shutil.copy(CANDIDATES_JSON, backup_path)
    
    with open(backup_path, 'r') as f:
        all_candidates = list(json.load(f)['functions'].keys())
    
    original_candidates_backup = backup_path
    print(f"Loaded {len(all_candidates)} total candidates from backup.")

    if os.path.exists(GOOD_FUNCTIONS_JSON):
        with open(GOOD_FUNCTIONS_JSON, 'r') as f:
            good_functions = set(json.load(f)['functions'].keys())
        print(f"Loaded {len(good_functions)} known good functions.")

    if os.path.exists(BAD_FUNCTIONS_TXT):
        with open(BAD_FUNCTIONS_TXT, 'r') as f:
            bad_functions = {line.strip() for line in f}
        print(f"Loaded {len(bad_functions)} known bad functions.")

    candidates_to_test = [f for f in all_candidates if f not in good_functions and f not in bad_functions]
    if not candidates_to_test:
        print("No new candidates to test. Exiting.")
        return
        
    print(f"Starting bisection with {len(candidates_to_test)} new candidates.")

    # --- Main Iterative Loop ---
    while True:
        if not candidates_to_test:
            print("All candidates have been classified.")
            break

        # Test the current pool of remaining candidates plus all known good ones.
        if run_make_test(good_functions.union(candidates_to_test)):
            # If they all pass, we're done! Add them all to the good set.
            print("SUCCESS: All remaining candidates are good!")
            good_functions.update(candidates_to_test)
            break
        else:
            # A failure occurred. Find exactly one bad function in the current pool.
            bad_func = find_one_bad_function(candidates_to_test)
            print(f"ISOLATED: Found bad function -> {bad_func}")
            
            # Add it to the bad list and remove from the pool to be tested.
            bad_functions.add(bad_func)
            candidates_to_test.remove(bad_func)
            print(f"Continuing with the remaining {len(candidates_to_test)} candidates.")
            # The loop will now restart, testing the remaining good candidates.

    # --- Finalization ---
    print("\n--- Bisection Complete ---")
    write_json_candidates(good_functions, GOOD_FUNCTIONS_JSON)
    print(f"Saved {len(good_functions)} good functions to {GOOD_FUNCTIONS_JSON}")
    
    with open(BAD_FUNCTIONS_TXT, 'w') as f:
        for func in sorted(list(bad_functions)):
            f.write(f"{func}\n")
    print(f"Saved {len(bad_functions)} bad functions to {BAD_FUNCTIONS_TXT}")
    
    print(f"Restoring original candidates file from {backup_path}")
    shutil.copy(backup_path, CANDIDATES_JSON)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nBisection interrupted. Restoring original candidates file.")
        if original_candidates_backup and os.path.exists(original_candidates_backup):
            shutil.copy(original_candidates_backup, CANDIDATES_JSON)
        sys.exit(1)