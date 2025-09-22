target triple = "x86_64-unknown-linux-gnu"

define internal i32 @opt_add(i32 %a, i32 %b) {   ; <-- internal linkage
entry:
  %s = add i32 %a, %b
  ret i32 %s
}

define i32 @caller(i32 %x, i32 %y) {
entry:
  %r = call i32 @opt_add(i32 %x, i32 %y)
  ret i32 %r
}
