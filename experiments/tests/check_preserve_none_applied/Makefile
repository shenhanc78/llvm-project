# Adjust if your build dir differs
LLVM_BUILD := ../../../build
OPT   := $(LLVM_BUILD)/bin/opt
CLANG := $(LLVM_BUILD)/bin/clang

all: opt-test

opt-test: out.ll
	@grep -n "preserve_nonecc" out.ll >/dev/null && \
	  echo "[OK] opt applied preserve_nonecc" || \
	  (echo "[FAIL] preserve_nonecc not found in out.ll"; exit 1)

out.ll: input.ll profile.json
	$(OPT) -preserve-none-enable \
	       -preserve-none-json=profile.json \
	       -passes="module(preserve-none-enable)" \
	       -S input.ll -o out.ll

clean:
	rm -f out.ll

.PHONY: all opt-test clean
