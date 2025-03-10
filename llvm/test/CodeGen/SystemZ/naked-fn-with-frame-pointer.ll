; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py UTC_ARGS: --version 5
; RUN: llc < %s -mtriple s390x | FileCheck %s -check-prefixes=CHECK

declare dso_local void @main()

define dso_local void @naked() naked "frame-pointer"="all" {
; CHECK-LABEL: naked:
; CHECK:       # %bb.0:
; CHECK-NEXT:    brasl %r14, main@PLT
  call void @main()
  unreachable
}

define dso_local void @normal() "frame-pointer"="all" {
; CHECK-LABEL: normal:
; CHECK:       # %bb.0:
; CHECK-NEXT:    stmg %r11, %r15, 88(%r15)
; CHECK-NEXT:    .cfi_offset %r11, -72
; CHECK-NEXT:    .cfi_offset %r14, -48
; CHECK-NEXT:    .cfi_offset %r15, -40
; CHECK-NEXT:    aghi %r15, -160
; CHECK-NEXT:    .cfi_def_cfa_offset 320
; CHECK-NEXT:    lgr %r11, %r15
; CHECK-NEXT:    .cfi_def_cfa_register %r11
; CHECK-NEXT:    brasl %r14, main@PLT
  call void @main()
  unreachable
}
