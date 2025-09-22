; ModuleID = 'input.ll'
source_filename = "input.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

define internal preserve_nonecc i32 @opt_add(i32 %a, i32 %b) {
entry:
  %s = add i32 %a, %b
  ret i32 %s
}

define i32 @caller(i32 %x, i32 %y) {
entry:
  %r = call preserve_nonecc i32 @opt_add(i32 %x, i32 %y)
  ret i32 %r
}
