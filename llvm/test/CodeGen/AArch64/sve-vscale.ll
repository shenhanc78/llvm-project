; RUN: llc -mtriple aarch64 -mattr=+sve -asm-verbose=0 < %s | FileCheck %s
; RUN: opt -mtriple=aarch64 -passes="require<profile-summary>,function(codegenprepare)" -S < %s | llc -mtriple=aarch64 -mattr=+sve -asm-verbose=0 | FileCheck %s

;
; RDVL
;

define i8 @rdvl_i8() nounwind {
; CHECK-LABEL: rdvl_i8:
; CHECK:       rdvl x0, #1
; CHECK-NEXT:  ret
  %vscale = call i8 @llvm.vscale.i8()
  %1 = mul nsw i8 %vscale, 16
  ret i8 %1
}

define i16 @rdvl_i16() nounwind {
; CHECK-LABEL: rdvl_i16:
; CHECK:       rdvl x0, #1
; CHECK-NEXT:  ret
  %vscale = call i16 @llvm.vscale.i16()
  %1 = mul nsw i16 %vscale, 16
  ret i16 %1
}

define i32 @rdvl_i32() nounwind {
; CHECK-LABEL: rdvl_i32:
; CHECK:       rdvl x0, #1
; CHECK-NEXT:  ret
  %vscale = call i32 @llvm.vscale.i32()
  %1 = mul nsw i32 %vscale, 16
  ret i32 %1
}

define i64 @rdvl_i64() nounwind {
; CHECK-LABEL: rdvl_i64:
; CHECK:       rdvl x0, #1
; CHECK-NEXT:  ret
  %vscale = call i64 @llvm.vscale.i64()
  %1 = mul nsw i64 %vscale, 16
  ret i64 %1
}

define i32 @rdvl_const() nounwind {
; CHECK-LABEL: rdvl_const:
; CHECK:       rdvl x0, #1
; CHECK-NEXT:  ret
  %vscale.ptr = getelementptr <vscale x 1 x i8>, ptr null, i64 1
  %vscale.int = ptrtoint ptr %vscale.ptr to i32
  %vscale.scaled = mul nsw i32 %vscale.int, 16
  ret i32 %vscale.scaled
}

define i32 @vscale_1() nounwind {
; CHECK-LABEL: vscale_1:
; CHECK:       rdvl [[TMP:x[0-9]+]], #1
; CHECK-NEXT:  lsr  x0, [[TMP]], #4
; CHECK-NEXT:  ret
  %vscale = call i32 @llvm.vscale.i32()
  ret i32 %vscale
}

define i32 @vscale_neg1() nounwind {
; CHECK-LABEL: vscale_neg1:
; CHECK:       rdvl [[TMP:x[0-9]+]], #-1
; CHECK-NEXT:  asr  x0, [[TMP]], #4
; CHECK-NEXT:  ret
  %vscale = call i32 @llvm.vscale.i32()
  %neg = mul nsw i32 -1, %vscale
  ret i32 %neg
}

define i32 @rdvl_3() nounwind {
; CHECK-LABEL: rdvl_3:
; CHECK:       rdvl [[VL_B:x[0-9]+]], #1
; CHECK-NEXT:  mov  w[[MUL:[0-9]+]], #3
; CHECK-NEXT:  lsr  [[VL_Q:x[0-9]+]], [[VL_B]], #4
; CHECK-NEXT:  mul  x0, [[VL_Q]], x[[MUL]]
; CHECK-NEXT:  ret
  %vscale = call i32 @llvm.vscale.i32()
  %1 = mul nsw i32 %vscale, 3
  ret i32 %1
}

define i32 @rdvl_min() nounwind {
; CHECK-LABEL: rdvl_min:
; CHECK:       rdvl x0, #-32
; CHECK-NEXT:  ret
  %vscale = call i32 @llvm.vscale.i32()
  %1 = mul nsw i32 %vscale, -512
  ret i32 %1
}

define i32 @rdvl_max() nounwind {
; CHECK-LABEL: rdvl_max:
; CHECK:       rdvl x0, #31
; CHECK-NEXT:  ret
  %vscale = call i32 @llvm.vscale.i32()
  %1 = mul nsw i32 %vscale, 496
  ret i32 %1
}

define i1 @rdvl_i1() {
; CHECK-LABEL: rdvl_i1:
; CHECK:         rdvl x8, #-1
; CHECK-NEXT:    asr x8, x8, #4
; CHECK-NEXT:    and w0, w8, #0x1
; CHECK-NEXT:    ret
  %a = tail call i64 @llvm.vscale.i64()
  %b = trunc i64 %a to i1
  ret i1 %b
}

;
; CNTH
;

define i32 @cnth() nounwind {
; CHECK-LABEL: cnth:
; CHECK:       cnth x0{{$}}
; CHECK-NEXT:  ret
  %vscale = call i32 @llvm.vscale.i32()
  %1 = shl nsw i32 %vscale, 3
  ret i32 %1
}

define i32 @cnth_max() nounwind {
; CHECK-LABEL: cnth_max:
; CHECK:       cnth x0, all, mul #15
; CHECK-NEXT:  ret
  %vscale = call i32 @llvm.vscale.i32()
  %1 = mul nsw i32 %vscale, 120
  ret i32 %1
}

define i32 @cnth_neg() nounwind {
; CHECK-LABEL: cnth_neg:
; CHECK:       cnth [[CNT:x[0-9]+]]
; CHECK:       neg x0, [[CNT]]
; CHECK-NEXT:  ret
  %vscale = call i32 @llvm.vscale.i32()
  %1 = mul nsw i32 %vscale, -8
  ret i32 %1
}

;
; CNTW
;

define i32 @cntw() nounwind {
; CHECK-LABEL: cntw:
; CHECK:       cntw x0{{$}}
; CHECK-NEXT:  ret
  %vscale = call i32 @llvm.vscale.i32()
  %1 = shl nsw i32 %vscale, 2
  ret i32 %1
}

define i32 @cntw_max() nounwind {
; CHECK-LABEL: cntw_max:
; CHECK:       cntw x0, all, mul #15
; CHECK-NEXT:  ret
  %vscale = call i32 @llvm.vscale.i32()
  %1 = mul nsw i32 %vscale, 60
  ret i32 %1
}

define i32 @cntw_neg() nounwind {
; CHECK-LABEL: cntw_neg:
; CHECK:       cntw [[CNT:x[0-9]+]]
; CHECK:       neg x0, [[CNT]]
; CHECK-NEXT:  ret
  %vscale = call i32 @llvm.vscale.i32()
  %1 = mul nsw i32 %vscale, -4
  ret i32 %1
}

;
; CNTD
;

define i32 @cntd() nounwind {
; CHECK-LABEL: cntd:
; CHECK:       cntd x0{{$}}
; CHECK-NEXT:  ret
  %vscale = call i32 @llvm.vscale.i32()
  %1 = shl nsw i32 %vscale, 1
  ret i32 %1
}

define i32 @cntd_max() nounwind {
; CHECK-LABEL: cntd_max:
; CHECK:       cntd x0, all, mul #15
; CHECK-NEXT:  ret
  %vscale = call i32 @llvm.vscale.i32()
  %1 = mul nsw i32 %vscale, 30
  ret i32 %1
}

define i32 @cntd_neg() nounwind {
; CHECK-LABEL: cntd_neg:
; CHECK:       cntd [[CNT:x[0-9]+]]
; CHECK:       neg x0, [[CNT]]
; CHECK-NEXT:  ret
  %vscale = call i32 @llvm.vscale.i32()
  %1 = mul nsw i32 %vscale, -2
  ret i32 %1
}

declare i8 @llvm.vscale.i8()
declare i16 @llvm.vscale.i16()
declare i32 @llvm.vscale.i32()
declare i64 @llvm.vscale.i64()
