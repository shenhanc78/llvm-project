# Experiments Playbook

This document explains how to run the end-to-end PreserveNone experiments that live under `llvm-project/experiments/`. It covers directory layout, the PreserveNone pass itself, and the workflow used to build profiled compilers, derive PreserveNone candidates, and benchmark the resulting Clang and MySQL builds.

## Directory tour

* `scripts/Makefile` — automation for building Clang toolchains (bootstrap → instrumentation → profile-guided builds), collecting liveness/IPRA data, and building variants that consume PreserveNone profiles. Targets create reproducible output trees under `~/ipra-run` and write metrics under `experiments/metrics/`.
* `scripts/*.py` — utilities that consume liveness output, compute PreserveNone candidates, run perf-based benchmarks, and analyze the results. Notable scripts:
  * `generate_pn_analysis_context.py` loads liveness/IPRA dumps and emits serialized context JSON for scoring.
  * `generate_liveness_profdata.py` scores the context to pick PreserveNone candidates and writes `liveness_profdata.json` that the pass consumes.
  * `perf_runner.py` runs perf-wrapped benchmarks (default commands point at Clang bench harnesses) and saves per-run logs.
  * `perf_analyzer.py` parses the perf logs, computes summary statistics, and emits an `analysis.txt` report.
* `lib/pylib/` — reusable helpers for parsing liveness dumps, graph algorithms, validators, and the PreserveNone cost model described in `lib/pylib/README.md`.
* `metrics/` — persisted experiment artifacts.
  * `metrics/liveness_output/` (created by Makefile targets) holds CS register liveness and IPRA dry-run dumps produced by the instrumented toolchains.
  * `metrics/pn_functions/` stores the serialized context (`costs.json`, `successors.json`, etc.) and `liveness_profdata.json` ranking files that drive the PreserveNone pass.
  * `metrics/references/` contains reference benchmark outputs and historical JSON files for comparison.
* `tests/` — regression cases for the PreserveNone pipeline. The `check_preserve_none_applied` fixture includes a profile JSON, source, and expected IR/object/assembly to ensure PreserveNone annotations are applied.

## PreserveNone pass: purpose and controls

`llvm/lib/Transforms/IPO/PreserveNonePass.cpp` implements a module pass that rewrites selected functions to use the `preserve_none` calling convention. The pass is gated by two command-line flags (forwarded via `-mllvm` in Clang/lld):

* `-preserve-none-enable` — hard enables the pass. If false, the pass is a no-op.
* `-preserve-none-json=<path>` — points at a JSON document of the form `{ "functions": { "foo": score, ... } }` that names functions eligible for conversion.

When enabled, the pass loads the JSON and processes matching functions. For non-address-taken functions, it rewrites both the function and its call sites to use `preserve_none` and disables tail calls. For address-taken functions, it clones the original to a new internal symbol suffixed with `.preserve_none`, retargets direct call sites to the clone, and leaves the original name as a stub that forwards to the clone so address-taking behavior remains valid. Modified functions are recorded to `-preserve-none-record` (default `./pn_functions.txt`).

The pass is wired into the ThinLTO post-link pipeline (see `llvm/lib/Passes/PassBuilderPipelines.cpp`) so builds need ThinLTO to invoke it automatically. Alternatively, it can be scheduled explicitly via the `preserve-none-enable` module pass name.

## End-to-end workflow (Clang and MySQL)

The experiment flow is split into three phases: compiler builds, candidate generation, and benchmarking/analysis. The same steps work for Clang or MySQL—only the benchmark commands differ.

### 1. Build compilers and collect liveness data (Makefile)

1. **Bootstrap a baseline compiler:**
   ```bash
   cd experiments/scripts
   make bootstrapped_clang
   ```
   This builds a release Clang/LLD toolchain at `~/ipra-run/bootstrapped_clang`.

2. **Produce a ThinLTO + AutoFDO baseline (common experiment path):**
   ThinLTO + AutoFDO is the most frequently exercised baseline for PreserveNone.
   ```bash
   make autofdo_metadata_clang        # build metadata-friendly clang
   make autofdo_collect_perf          # record perf samples (invokes clangbench by default)
   make autofdo_convert_profile       # convert perf.data to LLVM sample profile
   make thinlto_autofdo_clang         # build ThinLTO+AutoFDO baseline using the sample profile
   ```
   The final toolchain lives at `~/ipra-run/thinlto_autofdo_clang` and is what later steps use for liveness dumps and comparisons. If you want IPRA enabled throughout, use the analogous `ipra_thinlto_autofdo_clang` target.

3. **(Alternative) Instrumented + PGO baseline:**
   The original IR-instrumented PGO flow still exists when you need full instrumentation rather than sampled profiles.
   ```bash
   make instr_clang
   make instr_clang_data
   make fdo_clang
   ```
   These builds land in `~/ipra-run/instr_clang` and `~/ipra-run/fdo_clang` and can be substituted anywhere the ThinLTO AutoFDO baseline is referenced below.

4. **Generate liveness/IPRA dumps:**
   ```bash
   make thinlto_autofdo_liveness_analysis
   ```
   This configures a temporary ThinLTO + AutoFDO build with liveness analysis flags (`-enable-cs-reg-liveness-analysis` and IPRA dry run) and writes dumps to `metrics/liveness_output/thinlto_autofdo_liveness_output/`. If you built an IPRA baseline, use `make ipra_thinlto_autofdo_liveness_analysis`; for the instrumented PGO flow, run `make fdo_liveness_analysis` or its ThinLTO variants.

### 2. Derive PreserveNone candidates (Python)

1. **Serialize analysis context:**
   ```bash
   cd experiments/scripts
   python3 generate_pn_analysis_context.py
   ```
   The script reads the liveness/IPRA dumps for the configured `COMPILER` constant, validates them, and emits context JSON files (cost tables, call-site info, graph edges, hotness data, and dangerous function lists) under `metrics/pn_functions/<compiler>_pn_functions/`.

2. **Score functions and emit profile JSON:**
   ```bash
   python3 generate_liveness_profdata.py
   ```
   Using the serialized context and a whitelist in `metrics/pn_functions/good_functions.json`, the script scores each candidate with the cost model (`lib/pylib/scoring.py`) and writes `liveness_profdata.json` to the same directory. This is the file passed to `-preserve-none-json` when building PreserveNone-enabled toolchains.

### 3. Build PreserveNone-enabled toolchains (Makefile)

Use the generated `liveness_profdata.json` to build ThinLTO PGO toolchains that apply the pass:

```bash
make pn_fdo_clang            # PGO build using -preserve-none-enable/-preserve-none-json
make pn_thinlto_fdo_clang    # ThinLTO PGO variant
make pn_ipra_thinlto_fdo_clang
```

Each target injects the necessary `-mllvm -preserve-none-enable` and `-mllvm -preserve-none-json=<path>` flags into the build. ThinLTO targets also set the ThinLTO/LLD flags needed to reach the post-link pipeline where the pass runs.

### 4. Benchmark Clang or MySQL (Python)

1. **Run perf-based benchmarks:**
   Edit `COMMANDS` in `scripts/perf_runner.py` to point at the Clang or MySQL binaries you want to compare (e.g., PreserveNone vs. baseline). Then run:
   ```bash
   python3 perf_runner.py
   ```
   The script interleaves `perf stat` runs for each binary, saving per-run logs under `metrics/references/clangbench_results/clangbench_results_<timestamp>/`.

2. **Analyze results:**
   ```bash
   python3 perf_analyzer.py metrics/references/clangbench_results/clangbench_results_<timestamp>
   ```
   The analyzer parses the perf outputs, computes means/standard deviations, runs t-tests, and writes `analysis.txt` alongside the logs summarizing statistically significant differences in time and hardware counters.

3. **Visualize (optional):**
   The `scripts/visualizations/` notebooks (`mysql_vis.py`, `benchmark_visualization.ipynb`, `clangbench_visualization.ipynb`) can be opened to plot the collected metrics.

### 5. Inspect results and iterate

* The PreserveNone pass records modified function names to `pn_functions.txt` (or the path set via `-preserve-none-record`).
* The serialized context and `liveness_profdata.json` allow you to tweak thresholds or cost model parameters in `lib/pylib/scoring.py` and regenerate candidates.
* Rebuild the PreserveNone toolchains (`make pn_*`) and rerun `perf_runner.py`/`perf_analyzer.py` to compare iterations.

## How PreserveNone affects the build

* The pass activates during ThinLTO post-link when `-preserve-none-enable` is present. It reads `liveness_profdata.json` to decide which functions to retag or clone.
* Address-taken functions are cloned to `name.preserve_none` and the original becomes a stub so indirect calls keep a stable signature.
* Direct callers are retagged to use the new calling convention and have tail calls disabled to maintain correct preservation semantics.
* A record of rewritten functions is appended to the configured `-preserve-none-record` file, aiding regression tests under `experiments/tests/check_preserve_none_applied/`.

Following these steps produces reproducible PreserveNone-enabled Clang or MySQL binaries, benchmarks them with perf, and stores structured artifacts for downstream analysis and visualization.