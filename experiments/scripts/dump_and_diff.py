#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse, re, subprocess, sys
from pathlib import Path

# Function header lines look like:
#   0000000002f0b3a0 <_ZN5clang12LookupResult11resolveKindEv>:
HDR_RE = re.compile(r'^[0-9A-Fa-f]+\s+<([^>]+)>:\s*$')

def run(cmd):
    return subprocess.run(cmd, check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True).stdout

def objdump_disasm(objdump_bin: str, binary: str) -> str:
    # EXACTLY what you asked: objdump -d <binary>
    return run([objdump_bin, "-d", binary])

def extract_definition(disasm_text: str, mangled: str) -> str:
    """Capture exactly the block that starts at '<mangled>:' and ends before the next header."""
    capturing = False
    out_lines = []
    for line in disasm_text.splitlines():
        m = HDR_RE.match(line)
        if m:
            name = m.group(1)
            if capturing:
                # We just hit the next function header: stop capturing
                break
            if name == mangled:
                capturing = True
                out_lines = [line]
            continue
        if capturing:
            out_lines.append(line)
    return ("\n".join(out_lines).rstrip() + "\n") if out_lines else ""

def write(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)

def main():
    ap = argparse.ArgumentParser(description="Use 'objdump -d' to dump one function's definition from two binaries and diff them.")
    ap.add_argument("--before-binary", required=True, help="Path to BEFORE binary (e.g., /path/to/clang-21)")
    ap.add_argument("--after-binary",  required=True, help="Path to AFTER binary")
    ap.add_argument("--symbol",        required=True, help="MANGLED function name exactly as shown by objdump headers, e.g. _ZN5clang12LookupResult11resolveKindEv")
    ap.add_argument("--out-dir",       default="../metrics/references/asm", help="Output directory (default: ./asm)")
    ap.add_argument("--objdump",       default="objdump", help="objdump executable (default: objdump)")
    ap.add_argument("--before-out",    default="before.asm", help="Filename for BEFORE dump")
    ap.add_argument("--after-out",     default="after.asm",  help="Filename for AFTER dump")
    ap.add_argument("--diff-out",      default="diff.unified.diff", help="Filename for unified diff")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    before_path = out_dir / args.before_out
    after_path  = out_dir / args.after_out
    diff_path   = out_dir / args.diff_out

    # BEFORE
    dis_b = objdump_disasm(args.objdump, args.before_binary)
    blk_b = extract_definition(dis_b, args.symbol)
    if not blk_b:
        sys.exit(f"[before] definition not found for '{args.symbol}' in {args.before_binary}")
    write(before_path, blk_b)

    # AFTER
    dis_a = objdump_disasm(args.objdump, args.after_binary)
    blk_a = extract_definition(dis_a, args.symbol)
    if not blk_a:
        sys.exit(f"[after] definition not found for '{args.symbol}' in {args.after_binary}")
    write(after_path, blk_a)

    # Diff
    try:
        diff_txt = run(["diff", "-u", str(before_path), str(after_path)])
    except subprocess.CalledProcessError as e:
        diff_txt = e.stdout or ""  # nonzero exit when files differ is normal
    write(diff_path, diff_txt)

    print("Wrote:")
    print(" ", before_path)
    print(" ", after_path)
    print(" ", diff_path)

if __name__ == "__main__":
    main()

"""
python3 dump_and_diff.py \
  --before-binary  ../../../ipra-run/preserve_none_thinly_linked_fdo_clang/bin/clang-21 \
  --after-binary   ../../../ipra-run/thinly_linked_fdo_clang/bin/clang-21 \
  --symbol         gnosticsEngineEPNS_18CoverageSourceInfoE \
  --out-dir        ./asm \
  --objdump        objdump
"""