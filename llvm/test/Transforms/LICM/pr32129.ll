; NOTE: Assertions have been autogenerated by utils/update_test_checks.py UTC_ARGS: --version 2
; RUN: opt -S -passes=licm,simple-loop-unswitch,licm < %s | FileCheck %s

declare void @llvm.experimental.guard(i1, ...)

define void @test(i1 %arg) {
; CHECK-LABEL: define void @test
; CHECK-SAME: (i1 [[ARG:%.*]]) {
; CHECK-NEXT:  entry:
; CHECK-NEXT:    [[TMP0:%.*]] = icmp ult i32 0, 400
; CHECK-NEXT:    call void (i1, ...) @llvm.experimental.guard(i1 [[TMP0]], i32 9) [ "deopt"() ]
; CHECK-NEXT:    br i1 [[ARG]], label [[ENTRY_SPLIT:%.*]], label [[HEADER_SPLIT:%.*]]
; CHECK:       entry.split:
; CHECK-NEXT:    br label [[HEADER:%.*]]
; CHECK:       header.loopexit:
; CHECK-NEXT:    br label [[HEADER]]
; CHECK:       header:
; CHECK-NEXT:    br label [[LOOP:%.*]]
; CHECK:       header.split:
; CHECK-NEXT:    br label [[LOOP1:%.*]]
; CHECK:       loop:
; CHECK-NEXT:    br label [[LOOP1]]
;
entry:
  br label %header

header:
  br label %loop

loop:
  %0 = icmp ult i32 0, 400
  call void (i1, ...) @llvm.experimental.guard(i1 %0, i32 9) [ "deopt"() ]
  br i1 %arg, label %header, label %loop
}
