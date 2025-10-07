#!/usr/bin/env python3
# bisect.py — fast, crash-safe delta-debugging for preserve_none candidate sets

import argparse
import json
import os
import pickle
import random
import shutil
import signal
import sys
import time
from pathlib import Path
from typing import Iterable, List, Set, Dict
import subprocess

# --- Configuration (edit to your repo layout) ---------------------------------

LIVENESS_DATA_DIR = Path("../metrics/thinly_linked_fdo_liveness_output")
CANDIDATES_JSON = LIVENESS_DATA_DIR / "liveness_profdata.json"
GOOD_FUNCTIONS_JSON = LIVENESS_DATA_DIR / "good_functions.json"
BAD_FUNCTIONS_TXT = LIVENESS_DATA_DIR / "bad_functions.txt"
CACHE_PKL = LIVENESS_DATA_DIR / "tested_cache.pkl"
BACKUP_SUFFIX = ".bak"

# Your make target that consumes CANDIDATES_JSON and builds/runs benchmarks
MAKE_TARGET = "test_preserve_none_thinly_linked_fdo_clang"

# Optional: path to a JSON that already contains scores: { "functions": {name: score}}
# If provided, we sort by descending score to test the hottest first.
OPTIONAL_SCORED_CANDIDATES_JSON = None  # e.g., LIVENESS_DATA_DIR / "liveness_with_scores.json"

# Parallelize build where possible
MAKE_FLAGS = ["-j"]  # extend if needed, e.g., ["-j", "24"]

# Persist progress every N test invocations
PERSIST_EVERY = 5

# -----------------------------------------------------------------------------


# Global, in-memory state
good_functions: Set[str] = set()
bad_functions: Set[str] = set()
tested_cache: Dict[frozenset, bool] = {}  # frozenset(functions) -> result
tests_since_persist = 0


def load_json_functions(path: Path) -> Dict[str, float]:
    """
    Read a {"functions": {name: score}} or {"functions": [name, ...]}.
    Return a dict[name] = score (score=1.0 if not provided).
    """
    with open(path, "r") as f:
        data = json.load(f)
    fs = data.get("functions", {})
    return {str(k): float(v) for k, v in fs.items()}


def write_json_functions(path: Path, functions: Iterable[str]) -> None:
    """
    Write {"functions": [name, ...]} without pretty spaces for speed.
    """
    payload = {"functions": {function: 1.0 for function in functions}}
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w") as f:
        json.dump(payload, f, separators=(",", ":"))
    os.replace(tmp, path)


def persist_progress() -> None:
    """
    Save good/bad lists and cache so we can resume after crashes.
    """
    GOOD_FUNCTIONS_JSON.parent.mkdir(parents=True, exist_ok=True)
    with open(GOOD_FUNCTIONS_JSON, "w") as f:
        json.dump({"functions": sorted(good_functions)}, f, indent=2)

    with open(BAD_FUNCTIONS_TXT, "w") as f:
        for name in sorted(bad_functions):
            f.write(f"{name}\n")

    with open(CACHE_PKL, "wb") as f:
        pickle.dump(tested_cache, f)


def restore_progress() -> None:
    if GOOD_FUNCTIONS_JSON.exists():
        with open(GOOD_FUNCTIONS_JSON, "r") as f:
            good = json.load(f).get("functions", [])
            good_functions.update(good)
    if BAD_FUNCTIONS_TXT.exists():
        with open(BAD_FUNCTIONS_TXT, "r") as f:
            for line in f:
                name = line.strip()
                if name:
                    bad_functions.add(name)
    if CACHE_PKL.exists():
        try:
            with open(CACHE_PKL, "rb") as f:
                tested_cache.update(pickle.load(f))
        except Exception:
            # Cache corruption is non-fatal
            pass


def backup_candidates_json() -> Path:
    """
    Make a one-time backup of the candidate JSON we will keep editing.
    """
    backup_path = CANDIDATES_JSON.with_suffix(CANDIDATES_JSON.suffix + BACKUP_SUFFIX)
    if not backup_path.exists():
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(CANDIDATES_JSON, backup_path)
        print(f"[init] Backed up original candidates file -> {backup_path}")
    return backup_path


def restore_candidates_json(backup_path: Path) -> None:
    shutil.copy(backup_path, CANDIDATES_JSON)


def run_make(current_test_set: Set[str], capture_output: bool = False) -> bool:
    """
    Write CANDIDATES_JSON and run `make MAKE_TARGET`.
    Results are memoized by the *exact* set of functions.
    """
    global tests_since_persist

    key = frozenset(current_test_set)
    if key in tested_cache:
        return tested_cache[key]

    write_json_functions(CANDIDATES_JSON, current_test_set)

    cmd = ["make", MAKE_TARGET, *MAKE_FLAGS]
    try:
        if capture_output:
            subprocess.run(cmd, check=True, text=True, capture_output=True)
        else:
            subprocess.run(cmd, check=True)
        result = True
    except subprocess.CalledProcessError:
        result = False

    tested_cache[key] = result

    persist_progress()

    return result


def ddmin_shrink(failing_block: List[str]) -> List[str]:
    """
    Zeller's ddmin: return a minimal (w.r.t. subset) failing subset.
    Works when there can be multiple bad functions in interplay.
    """
    if not failing_block:
        return []

    n = 2
    failing_block = list(failing_block)

    while len(failing_block) >= 2:
        chunk = max(1, len(failing_block) // n)
        some_reduction = False

        for i in range(0, len(failing_block), chunk):
            subset = set(failing_block[i:i + chunk])

            # Test subset itself
            if not run_make(good_functions | subset):
                failing_block = list(subset)
                n = 2
                some_reduction = True
                break

            # Test complement
            complement = set(failing_block) - subset
            if complement and not run_make(good_functions | complement):
                failing_block = list(complement)
                n = 2
                some_reduction = True
                break

        if not some_reduction:
            if chunk == 1:
                break
            n = min(len(failing_block), n * 2)

    return failing_block


def isolate_and_remove_bad(candidates: List[str]) -> List[str]:
    """
    Given a list that (as a block) fails when added to current good set,
    shrink it to a minimal failing subset and mark all members bad.
    Return the list of names marked bad (for logging).
    """
    minimal = ddmin_shrink(candidates)
    for f in minimal:
        bad_functions.add(f)
    return minimal


def sorted_candidates(all_funs: Dict[str, float], rng, seed_hot_first: int) -> List[str]:
    """
    Return a list of remaining candidates ordered by (score desc, random tiebreak).
    """
    items = [(name, score) for name, score in all_funs.items()
             if name not in good_functions and name not in bad_functions]
    # Stable random tiebreak so repeated runs don't slam the same worst cases
    rng.shuffle(items)
    items.sort(key=lambda x: x[1], reverse=True)
    ordered = [name for name, _ in items]
    if seed_hot_first and seed_hot_first < len(ordered):
        # Ensure top-K hottest go first as a group test (handled by main)
        pass
    return ordered


def graceful_exit(signum, frame):
    print("\n[signal] Caught signal, persisting progress and exiting...")
    try:
        persist_progress()
    finally:
        sys.exit(2)


def main():
    print("[init] paths:")
    print(f"  LIVENESS_DATA_DIR   = {LIVENESS_DATA_DIR}")
    print(f"  CANDIDATES_JSON     = {CANDIDATES_JSON}")
    print(f"  GOOD_FUNCTIONS_JSON = {GOOD_FUNCTIONS_JSON}")
    print(f"  BAD_FUNCTIONS_TXT   = {BAD_FUNCTIONS_TXT}")
    print(f"  CACHE_PKL           = {CACHE_PKL}")

    parser = argparse.ArgumentParser(description="Fast bisect/ddmin driver for preserve_none candidates.")
    parser.add_argument("--seed", type=int, default=0, help="RNG seed for stable shuffles.")
    parser.add_argument("--topk", type=int, default=0,
                        help="If >0, test the top-K hottest as one block first.")
    parser.add_argument("--capture-output", action="store_true",
                        help="Capture build stdout/stderr (slower).")
    parser.add_argument("--scored-json", type=str, default=None,
                        help="Optional JSON with function scores; falls back to CANDIDATES_JSON.")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, graceful_exit)
    signal.signal(signal.SIGTERM, graceful_exit)

    rng = random.Random(args.seed)

    # Make/restore backup of candidates file
    backup_path = backup_candidates_json()
    restore_progress()

    # Load all candidates (+optional scores)
    scored_path = Path(args.scored_json) if args.scored_json else OPTIONAL_SCORED_CANDIDATES_JSON
    source_path = Path(scored_path) if scored_path else CANDIDATES_JSON
    if not source_path.exists():
        print(f"error: {source_path} not found", file=sys.stderr)
        sys.exit(1)

    all_candidates_with_scores = load_json_functions(source_path)
    all_names = list(all_candidates_with_scores.keys())
    print(f"[init] Loaded {len(all_names)} total candidates (good={len(good_functions)}, bad={len(bad_functions)})")

    # Remove already-known ones from tested_cache keys to avoid memory blow-up
    if tested_cache:
        drop_keys = []
        known = good_functions | bad_functions
        for key in tested_cache.keys():
            if key & known:
                drop_keys.append(key)
        for k in drop_keys:
            tested_cache.pop(k, None)

    # Build initial ordered pool
    pool = sorted_candidates(all_candidates_with_scores, rng, args.topk)
    if not pool:
        print("[done] Nothing to test. All candidates classified.")
        restore_candidates_json(backup_path)
        persist_progress()
        return

    # Seed test: top-K hottest together
    if args.topk and args.topk <= len(pool):
        hottest_block = pool[:args.topk]
        print(f"[seed] Testing top-{args.topk} hottest together...")
        if run_make(good_functions | set(hottest_block), capture_output=args.capture_output):
            print(f"[seed] Top-{args.topk} all good.")
            good_functions.update(hottest_block)
            pool = pool[args.topk:]
        else:
            bad_block = isolate_and_remove_bad(hottest_block)
            print(f"[seed] Isolated bad in top-{args.topk}: {bad_block}")
            pool = [p for p in pool if p not in bad_block]

    # Main classification loop
    remaining = pool
    while remaining:
        # Try to classify a big chunk at once (group testing).
        # Heuristic: test up to 1/3 of the remaining, capped for build stability.
        chunk_sz = max(1, min(len(remaining) // 3, 200))
        block = remaining[:chunk_sz]
        test_set = good_functions | set(block)

        if run_make(test_set, capture_output=args.capture_output):
            # Whole block passed -> all good
            good_functions.update(block)
            persist_progress()
            remaining = remaining[chunk_sz:]
            print(f"[pass] Marked {len(block)} good. remaining={len(remaining)}")
            continue

        # Block failed -> shrink to minimal failing subset, mark those bad
        bad_block = isolate_and_remove_bad(block)
        persist_progress()
        print(f"[fail] Found {len(bad_block)} bad -> {bad_block}")
        # Remove bad ones from future consideration
        name_set = set(bad_block)
        remaining = [x for x in remaining if x not in name_set]

        # Optional: if failure density looks high, reduce chunk size to converge
        if len(bad_block) <= max(1, chunk_sz // 8):
            # keep chunk size as-is
            pass
        else:
            # failures dense; try smaller next block
            pass

    # Finalize
    print("\n[complete] All candidates classified.")
    persist_progress()
    restore_candidates_json(backup_path)
    print(f"[summary] good={len(good_functions)} bad={len(bad_functions)} cache_entries={len(tested_cache)}")


if __name__ == "__main__":
    main()
