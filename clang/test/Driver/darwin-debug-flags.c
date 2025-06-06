// RUN: env RC_DEBUG_OPTIONS=1 %clang -target i386-apple-darwin11 -I "path with \spaces" -g -Os %s  -emit-llvm -S -o - | FileCheck %s
// RUN: touch %t.s
// RUN: env RC_DEBUG_OPTIONS=1 %clang -### -target i386-apple-darwin11 -c -g %t.s 2>&1 | FileCheck -check-prefix=S %s
// RUN: %clang -### -target i386-apple-darwin11 -c -g %t.s 2>&1 | FileCheck -check-prefix=P %s

// CHECK: distinct !DICompileUnit(
// CHECK-SAME:                flags:
// CHECK-SAME:                -I path\\ with\\ \\\\spaces
// CHECK-SAME:                -g -Os
// CHECK-SAME:                -mmacos-version-min=10.7

int x;

// S: "-dwarf-debug-flags"

// P: "-dwarf-debug-producer"
