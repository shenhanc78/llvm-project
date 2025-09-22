; Force System V x86-64
target triple = "x86_64-unknown-linux-gnu"

; Callee: does a tiny add, but also has inline asm that clobbers RBX.
; Under the default C calling convention, RBX is callee-saved -> prologue/epilogue save/restore.
; Under preserve_none, callee may clobber RBX -> no save/restore needed.
define internal i64 @opt_add(i64 %a, i64 %b) nounwind noinline {
entry:
  %sum = add i64 %a, %b

  ; Inline asm with an explicit clobber of RBX (and usual flags).
  ; Empty template is fine; the clobber is what matters.
  call void asm sideeffect "", "~{rbx},~{dirflag},~{fpsr},~{flags}"()

  ret i64 %sum
}

; Caller: just calls opt_add. Keep it external so we can see both sides.
define i64 @caller(i64 %x, i64 %y) nounwind {
entry:
  %r = call i64 @opt_add(i64 %x, i64 %y)
  ret i64 %r
}
