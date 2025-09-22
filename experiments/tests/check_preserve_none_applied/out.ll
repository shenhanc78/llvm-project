; ModuleID = 'input.ll'
source_filename = "input.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

; Function Attrs: noinline nounwind
define internal preserve_nonecc i64 @opt_add(i64 %a, i64 %b) #0 {
entry:
  %sum = add i64 %a, %b
  call void asm sideeffect "", "~{rbx},~{dirflag},~{fpsr},~{flags}"()
  ret i64 %sum
}

; Function Attrs: nounwind
define i64 @caller(i64 %x, i64 %y) #1 {
entry:
  %r = call preserve_nonecc i64 @opt_add(i64 %x, i64 %y)
  ret i64 %r
}

attributes #0 = { noinline nounwind }
attributes #1 = { nounwind }
