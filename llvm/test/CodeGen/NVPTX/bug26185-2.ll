; RUN: llc < %s -mtriple=nvptx64 -mcpu=sm_35 -verify-machineinstrs | FileCheck %s
; RUN: %if ptxas %{ llc < %s -mtriple=nvptx64 -mcpu=sm_35 | %ptxas-verify %}

; Verify that we correctly emit code for extending ldg/ldu. We do not expose
; extending variants in the backend, but the ldg/ldu selection code may pick
; extending loads as candidates. We do want to support this, so make sure we
; emit the necessary cvt.* instructions to implement the extension and let ptxas
; emit the real extending loads.

target datalayout = "e-i64:64-v16:16-v32:32-n16:32:64"
target triple = "nvptx64-nvidia-cuda"

; CHECK-LABEL: spam
define ptx_kernel void @spam(ptr addrspace(1) noalias nocapture readonly %arg, ptr addrspace(1) noalias nocapture %arg1, i64 %arg2, i64 %arg3) #0 {
bb:
  %tmp5 = add nsw i64 %arg3, 8
  %tmp6 = getelementptr i16, ptr addrspace(1) %arg, i64 %tmp5
; CHECK: ld.global.nc.b16
  %tmp7 = load i16, ptr addrspace(1) %tmp6, align 2
; CHECK: cvt.s32.s16
  %tmp8 = sext i16 %tmp7 to i64
  %tmp9 = mul nsw i64 %tmp8, %tmp8
  %tmp10 = load i64, ptr addrspace(1) %arg1, align 8
  %tmp11 = add nsw i64 %tmp9, %tmp10
  store i64 %tmp11, ptr addrspace(1) %arg1, align 8
  ret void
}

attributes #0 = { norecurse nounwind "polly.skip.fn" "nvvm.maxntid"="1,1,1" }
