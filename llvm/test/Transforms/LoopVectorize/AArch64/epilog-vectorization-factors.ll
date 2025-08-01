; NOTE: Assertions have been autogenerated by utils/update_test_checks.py
; RUN: opt -S < %s -passes=loop-vectorize -force-vector-interleave=4 2>&1 | FileCheck %s

target datalayout = "e-m:e-i64:64-i128:128-n32:64-S128"
target triple = "aarch64"

define void @add_i8(ptr noalias nocapture noundef writeonly %A, ptr nocapture noundef readonly %B, ptr nocapture noundef readonly %C, i64 noundef %Iterations) {
; CHECK-LABEL: @add_i8(
; CHECK-NEXT:  iter.check:
; CHECK-NEXT:    [[MIN_ITERS_CHECK:%.*]] = icmp ult i64 [[ITERATIONS:%.*]], 8
; CHECK-NEXT:    br i1 [[MIN_ITERS_CHECK]], label [[VEC_EPILOG_SCALAR_PH:%.*]], label [[VECTOR_MAIN_LOOP_ITER_CHECK:%.*]]
; CHECK:       vector.main.loop.iter.check:
; CHECK-NEXT:    [[MIN_ITERS_CHECK1:%.*]] = icmp ult i64 [[ITERATIONS]], 64
; CHECK-NEXT:    br i1 [[MIN_ITERS_CHECK1]], label [[VEC_EPILOG_PH:%.*]], label [[VECTOR_PH:%.*]]
; CHECK:       vector.ph:
; CHECK-NEXT:    [[N_MOD_VF:%.*]] = urem i64 [[ITERATIONS]], 64
; CHECK-NEXT:    [[N_VEC:%.*]] = sub i64 [[ITERATIONS]], [[N_MOD_VF]]
; CHECK-NEXT:    br label [[VECTOR_BODY:%.*]]
; CHECK:       vector.body:
; CHECK-NEXT:    [[INDEX:%.*]] = phi i64 [ 0, [[VECTOR_PH]] ], [ [[INDEX_NEXT:%.*]], [[VECTOR_BODY]] ]
; CHECK-NEXT:    [[TMP1:%.*]] = getelementptr inbounds i8, ptr [[B:%.*]], i64 [[INDEX]]
; CHECK-NEXT:    [[TMP3:%.*]] = getelementptr inbounds i8, ptr [[TMP1]], i32 16
; CHECK-NEXT:    [[TMP4:%.*]] = getelementptr inbounds i8, ptr [[TMP1]], i32 32
; CHECK-NEXT:    [[TMP5:%.*]] = getelementptr inbounds i8, ptr [[TMP1]], i32 48
; CHECK-NEXT:    [[WIDE_LOAD:%.*]] = load <16 x i8>, ptr [[TMP1]], align 1
; CHECK-NEXT:    [[WIDE_LOAD2:%.*]] = load <16 x i8>, ptr [[TMP3]], align 1
; CHECK-NEXT:    [[WIDE_LOAD3:%.*]] = load <16 x i8>, ptr [[TMP4]], align 1
; CHECK-NEXT:    [[WIDE_LOAD4:%.*]] = load <16 x i8>, ptr [[TMP5]], align 1
; CHECK-NEXT:    [[TMP6:%.*]] = getelementptr inbounds i8, ptr [[C:%.*]], i64 [[INDEX]]
; CHECK-NEXT:    [[TMP8:%.*]] = getelementptr inbounds i8, ptr [[TMP6]], i32 16
; CHECK-NEXT:    [[TMP9:%.*]] = getelementptr inbounds i8, ptr [[TMP6]], i32 32
; CHECK-NEXT:    [[TMP10:%.*]] = getelementptr inbounds i8, ptr [[TMP6]], i32 48
; CHECK-NEXT:    [[WIDE_LOAD5:%.*]] = load <16 x i8>, ptr [[TMP6]], align 1
; CHECK-NEXT:    [[WIDE_LOAD6:%.*]] = load <16 x i8>, ptr [[TMP8]], align 1
; CHECK-NEXT:    [[WIDE_LOAD7:%.*]] = load <16 x i8>, ptr [[TMP9]], align 1
; CHECK-NEXT:    [[WIDE_LOAD8:%.*]] = load <16 x i8>, ptr [[TMP10]], align 1
; CHECK-NEXT:    [[TMP11:%.*]] = add <16 x i8> [[WIDE_LOAD5]], [[WIDE_LOAD]]
; CHECK-NEXT:    [[TMP12:%.*]] = add <16 x i8> [[WIDE_LOAD6]], [[WIDE_LOAD2]]
; CHECK-NEXT:    [[TMP13:%.*]] = add <16 x i8> [[WIDE_LOAD7]], [[WIDE_LOAD3]]
; CHECK-NEXT:    [[TMP14:%.*]] = add <16 x i8> [[WIDE_LOAD8]], [[WIDE_LOAD4]]
; CHECK-NEXT:    [[TMP15:%.*]] = getelementptr inbounds i8, ptr [[A:%.*]], i64 [[INDEX]]
; CHECK-NEXT:    [[TMP17:%.*]] = getelementptr inbounds i8, ptr [[TMP15]], i32 16
; CHECK-NEXT:    [[TMP18:%.*]] = getelementptr inbounds i8, ptr [[TMP15]], i32 32
; CHECK-NEXT:    [[TMP19:%.*]] = getelementptr inbounds i8, ptr [[TMP15]], i32 48
; CHECK-NEXT:    store <16 x i8> [[TMP11]], ptr [[TMP15]], align 1
; CHECK-NEXT:    store <16 x i8> [[TMP12]], ptr [[TMP17]], align 1
; CHECK-NEXT:    store <16 x i8> [[TMP13]], ptr [[TMP18]], align 1
; CHECK-NEXT:    store <16 x i8> [[TMP14]], ptr [[TMP19]], align 1
; CHECK-NEXT:    [[INDEX_NEXT]] = add nuw i64 [[INDEX]], 64
; CHECK-NEXT:    [[TMP20:%.*]] = icmp eq i64 [[INDEX_NEXT]], [[N_VEC]]
; CHECK-NEXT:    br i1 [[TMP20]], label [[MIDDLE_BLOCK:%.*]], label [[VECTOR_BODY]], !llvm.loop [[LOOP0:![0-9]+]]
; CHECK:       middle.block:
; CHECK-NEXT:    [[CMP_N:%.*]] = icmp eq i64 [[ITERATIONS]], [[N_VEC]]
; CHECK-NEXT:    br i1 [[CMP_N]], label [[EXIT:%.*]], label [[VEC_EPILOG_ITER_CHECK:%.*]]
; CHECK:       vec.epilog.iter.check:
; CHECK-NEXT:    [[N_VEC_REMAINING:%.*]] = sub i64 [[ITERATIONS]], [[N_VEC]]
; CHECK-NEXT:    [[MIN_EPILOG_ITERS_CHECK:%.*]] = icmp ult i64 [[N_VEC_REMAINING]], 8
; CHECK-NEXT:    br i1 [[MIN_EPILOG_ITERS_CHECK]], label [[VEC_EPILOG_SCALAR_PH]], label [[VEC_EPILOG_PH]]
; CHECK:       vec.epilog.ph:
; CHECK-NEXT:    [[VEC_EPILOG_RESUME_VAL:%.*]] = phi i64 [ [[N_VEC]], [[VEC_EPILOG_ITER_CHECK]] ], [ 0, [[VECTOR_MAIN_LOOP_ITER_CHECK]] ]
; CHECK-NEXT:    [[N_MOD_VF9:%.*]] = urem i64 [[ITERATIONS]], 8
; CHECK-NEXT:    [[N_VEC10:%.*]] = sub i64 [[ITERATIONS]], [[N_MOD_VF9]]
; CHECK-NEXT:    br label [[VEC_EPILOG_VECTOR_BODY:%.*]]
; CHECK:       vec.epilog.vector.body:
; CHECK-NEXT:    [[INDEX11:%.*]] = phi i64 [ [[VEC_EPILOG_RESUME_VAL]], [[VEC_EPILOG_PH]] ], [ [[INDEX_NEXT14:%.*]], [[VEC_EPILOG_VECTOR_BODY]] ]
; CHECK-NEXT:    [[TMP22:%.*]] = getelementptr inbounds i8, ptr [[B]], i64 [[INDEX11]]
; CHECK-NEXT:    [[WIDE_LOAD12:%.*]] = load <8 x i8>, ptr [[TMP22]], align 1
; CHECK-NEXT:    [[TMP24:%.*]] = getelementptr inbounds i8, ptr [[C]], i64 [[INDEX11]]
; CHECK-NEXT:    [[WIDE_LOAD13:%.*]] = load <8 x i8>, ptr [[TMP24]], align 1
; CHECK-NEXT:    [[TMP26:%.*]] = add <8 x i8> [[WIDE_LOAD13]], [[WIDE_LOAD12]]
; CHECK-NEXT:    [[TMP27:%.*]] = getelementptr inbounds i8, ptr [[A]], i64 [[INDEX11]]
; CHECK-NEXT:    store <8 x i8> [[TMP26]], ptr [[TMP27]], align 1
; CHECK-NEXT:    [[INDEX_NEXT14]] = add nuw i64 [[INDEX11]], 8
; CHECK-NEXT:    [[TMP29:%.*]] = icmp eq i64 [[INDEX_NEXT14]], [[N_VEC10]]
; CHECK-NEXT:    br i1 [[TMP29]], label [[VEC_EPILOG_MIDDLE_BLOCK:%.*]], label [[VEC_EPILOG_VECTOR_BODY]], !llvm.loop [[LOOP3:![0-9]+]]
; CHECK:       vec.epilog.middle.block:
; CHECK-NEXT:    [[CMP_N15:%.*]] = icmp eq i64 [[ITERATIONS]], [[N_VEC10]]
; CHECK-NEXT:    br i1 [[CMP_N15]], label [[EXIT]], label [[VEC_EPILOG_SCALAR_PH]]
; CHECK:       vec.epilog.scalar.ph:
; CHECK-NEXT:    [[BC_RESUME_VAL:%.*]] = phi i64 [ [[N_VEC10]], [[VEC_EPILOG_MIDDLE_BLOCK]] ], [ [[N_VEC]], [[VEC_EPILOG_ITER_CHECK]] ], [ 0, [[ITER_CHECK:%.*]] ]
; CHECK-NEXT:    br label [[FOR_BODY:%.*]]
; CHECK:       for.body:
; CHECK-NEXT:    [[IV:%.*]] = phi i64 [ [[BC_RESUME_VAL]], [[VEC_EPILOG_SCALAR_PH]] ], [ [[IV_NEXT:%.*]], [[FOR_BODY]] ]
; CHECK-NEXT:    [[ARRAYIDX:%.*]] = getelementptr inbounds i8, ptr [[B]], i64 [[IV]]
; CHECK-NEXT:    [[TMP30:%.*]] = load i8, ptr [[ARRAYIDX]], align 1
; CHECK-NEXT:    [[ARRAYIDX2:%.*]] = getelementptr inbounds i8, ptr [[C]], i64 [[IV]]
; CHECK-NEXT:    [[TMP31:%.*]] = load i8, ptr [[ARRAYIDX2]], align 1
; CHECK-NEXT:    [[ADD:%.*]] = add i8 [[TMP31]], [[TMP30]]
; CHECK-NEXT:    [[ARRAYIDX6:%.*]] = getelementptr inbounds i8, ptr [[A]], i64 [[IV]]
; CHECK-NEXT:    store i8 [[ADD]], ptr [[ARRAYIDX6]], align 1
; CHECK-NEXT:    [[IV_NEXT]] = add nuw nsw i64 [[IV]], 1
; CHECK-NEXT:    [[EXITCOND_NOT:%.*]] = icmp eq i64 [[IV_NEXT]], [[ITERATIONS]]
; CHECK-NEXT:    br i1 [[EXITCOND_NOT]], label [[EXIT]], label [[FOR_BODY]], !llvm.loop [[LOOP4:![0-9]+]]
; CHECK:       exit:
; CHECK-NEXT:    ret void
;
entry:
  br label %for.body

for.body:
  %iv = phi i64 [ 0, %entry ], [ %iv.next, %for.body ]
  %arrayidx = getelementptr inbounds i8, ptr %B, i64 %iv
  %0 = load i8, ptr %arrayidx, align 1
  %arrayidx2 = getelementptr inbounds i8, ptr %C, i64 %iv
  %1 = load i8, ptr %arrayidx2, align 1
  %add = add i8 %1, %0
  %arrayidx6 = getelementptr inbounds i8, ptr %A, i64 %iv
  store i8 %add, ptr %arrayidx6, align 1
  %iv.next = add nuw nsw i64 %iv, 1
  %exitcond.not = icmp eq i64 %iv.next, %Iterations
  br i1 %exitcond.not, label %exit, label %for.body

exit:
  ret void
}

define void @add_i16(ptr noalias nocapture noundef writeonly %A, ptr nocapture noundef readonly %B, ptr nocapture noundef readonly %C, i64 noundef %Iterations) {
; CHECK-LABEL: @add_i16(
; CHECK-NEXT:  iter.check:
; CHECK-NEXT:    [[MIN_ITERS_CHECK:%.*]] = icmp ult i64 [[ITERATIONS:%.*]], 4
; CHECK-NEXT:    br i1 [[MIN_ITERS_CHECK]], label [[VEC_EPILOG_SCALAR_PH:%.*]], label [[VECTOR_MAIN_LOOP_ITER_CHECK:%.*]]
; CHECK:       vector.main.loop.iter.check:
; CHECK-NEXT:    [[MIN_ITERS_CHECK1:%.*]] = icmp ult i64 [[ITERATIONS]], 32
; CHECK-NEXT:    br i1 [[MIN_ITERS_CHECK1]], label [[VEC_EPILOG_PH:%.*]], label [[VECTOR_PH:%.*]]
; CHECK:       vector.ph:
; CHECK-NEXT:    [[N_MOD_VF:%.*]] = urem i64 [[ITERATIONS]], 32
; CHECK-NEXT:    [[N_VEC:%.*]] = sub i64 [[ITERATIONS]], [[N_MOD_VF]]
; CHECK-NEXT:    br label [[VECTOR_BODY:%.*]]
; CHECK:       vector.body:
; CHECK-NEXT:    [[INDEX:%.*]] = phi i64 [ 0, [[VECTOR_PH]] ], [ [[INDEX_NEXT:%.*]], [[VECTOR_BODY]] ]
; CHECK-NEXT:    [[TMP1:%.*]] = getelementptr inbounds i16, ptr [[B:%.*]], i64 [[INDEX]]
; CHECK-NEXT:    [[TMP3:%.*]] = getelementptr inbounds i16, ptr [[TMP1]], i32 8
; CHECK-NEXT:    [[TMP4:%.*]] = getelementptr inbounds i16, ptr [[TMP1]], i32 16
; CHECK-NEXT:    [[TMP5:%.*]] = getelementptr inbounds i16, ptr [[TMP1]], i32 24
; CHECK-NEXT:    [[WIDE_LOAD:%.*]] = load <8 x i16>, ptr [[TMP1]], align 1
; CHECK-NEXT:    [[WIDE_LOAD2:%.*]] = load <8 x i16>, ptr [[TMP3]], align 1
; CHECK-NEXT:    [[WIDE_LOAD3:%.*]] = load <8 x i16>, ptr [[TMP4]], align 1
; CHECK-NEXT:    [[WIDE_LOAD4:%.*]] = load <8 x i16>, ptr [[TMP5]], align 1
; CHECK-NEXT:    [[TMP6:%.*]] = getelementptr inbounds i16, ptr [[C:%.*]], i64 [[INDEX]]
; CHECK-NEXT:    [[TMP8:%.*]] = getelementptr inbounds i16, ptr [[TMP6]], i32 8
; CHECK-NEXT:    [[TMP9:%.*]] = getelementptr inbounds i16, ptr [[TMP6]], i32 16
; CHECK-NEXT:    [[TMP10:%.*]] = getelementptr inbounds i16, ptr [[TMP6]], i32 24
; CHECK-NEXT:    [[WIDE_LOAD5:%.*]] = load <8 x i16>, ptr [[TMP6]], align 1
; CHECK-NEXT:    [[WIDE_LOAD6:%.*]] = load <8 x i16>, ptr [[TMP8]], align 1
; CHECK-NEXT:    [[WIDE_LOAD7:%.*]] = load <8 x i16>, ptr [[TMP9]], align 1
; CHECK-NEXT:    [[WIDE_LOAD8:%.*]] = load <8 x i16>, ptr [[TMP10]], align 1
; CHECK-NEXT:    [[TMP11:%.*]] = add <8 x i16> [[WIDE_LOAD5]], [[WIDE_LOAD]]
; CHECK-NEXT:    [[TMP12:%.*]] = add <8 x i16> [[WIDE_LOAD6]], [[WIDE_LOAD2]]
; CHECK-NEXT:    [[TMP13:%.*]] = add <8 x i16> [[WIDE_LOAD7]], [[WIDE_LOAD3]]
; CHECK-NEXT:    [[TMP14:%.*]] = add <8 x i16> [[WIDE_LOAD8]], [[WIDE_LOAD4]]
; CHECK-NEXT:    [[TMP15:%.*]] = getelementptr inbounds i16, ptr [[A:%.*]], i64 [[INDEX]]
; CHECK-NEXT:    [[TMP17:%.*]] = getelementptr inbounds i16, ptr [[TMP15]], i32 8
; CHECK-NEXT:    [[TMP18:%.*]] = getelementptr inbounds i16, ptr [[TMP15]], i32 16
; CHECK-NEXT:    [[TMP19:%.*]] = getelementptr inbounds i16, ptr [[TMP15]], i32 24
; CHECK-NEXT:    store <8 x i16> [[TMP11]], ptr [[TMP15]], align 1
; CHECK-NEXT:    store <8 x i16> [[TMP12]], ptr [[TMP17]], align 1
; CHECK-NEXT:    store <8 x i16> [[TMP13]], ptr [[TMP18]], align 1
; CHECK-NEXT:    store <8 x i16> [[TMP14]], ptr [[TMP19]], align 1
; CHECK-NEXT:    [[INDEX_NEXT]] = add nuw i64 [[INDEX]], 32
; CHECK-NEXT:    [[TMP20:%.*]] = icmp eq i64 [[INDEX_NEXT]], [[N_VEC]]
; CHECK-NEXT:    br i1 [[TMP20]], label [[MIDDLE_BLOCK:%.*]], label [[VECTOR_BODY]], !llvm.loop [[LOOP5:![0-9]+]]
; CHECK:       middle.block:
; CHECK-NEXT:    [[CMP_N:%.*]] = icmp eq i64 [[ITERATIONS]], [[N_VEC]]
; CHECK-NEXT:    br i1 [[CMP_N]], label [[EXIT:%.*]], label [[VEC_EPILOG_ITER_CHECK:%.*]]
; CHECK:       vec.epilog.iter.check:
; CHECK-NEXT:    [[N_VEC_REMAINING:%.*]] = sub i64 [[ITERATIONS]], [[N_VEC]]
; CHECK-NEXT:    [[MIN_EPILOG_ITERS_CHECK:%.*]] = icmp ult i64 [[N_VEC_REMAINING]], 4
; CHECK-NEXT:    br i1 [[MIN_EPILOG_ITERS_CHECK]], label [[VEC_EPILOG_SCALAR_PH]], label [[VEC_EPILOG_PH]]
; CHECK:       vec.epilog.ph:
; CHECK-NEXT:    [[VEC_EPILOG_RESUME_VAL:%.*]] = phi i64 [ [[N_VEC]], [[VEC_EPILOG_ITER_CHECK]] ], [ 0, [[VECTOR_MAIN_LOOP_ITER_CHECK]] ]
; CHECK-NEXT:    [[N_MOD_VF9:%.*]] = urem i64 [[ITERATIONS]], 4
; CHECK-NEXT:    [[N_VEC10:%.*]] = sub i64 [[ITERATIONS]], [[N_MOD_VF9]]
; CHECK-NEXT:    br label [[VEC_EPILOG_VECTOR_BODY:%.*]]
; CHECK:       vec.epilog.vector.body:
; CHECK-NEXT:    [[INDEX11:%.*]] = phi i64 [ [[VEC_EPILOG_RESUME_VAL]], [[VEC_EPILOG_PH]] ], [ [[INDEX_NEXT14:%.*]], [[VEC_EPILOG_VECTOR_BODY]] ]
; CHECK-NEXT:    [[TMP22:%.*]] = getelementptr inbounds i16, ptr [[B]], i64 [[INDEX11]]
; CHECK-NEXT:    [[WIDE_LOAD12:%.*]] = load <4 x i16>, ptr [[TMP22]], align 1
; CHECK-NEXT:    [[TMP24:%.*]] = getelementptr inbounds i16, ptr [[C]], i64 [[INDEX11]]
; CHECK-NEXT:    [[WIDE_LOAD13:%.*]] = load <4 x i16>, ptr [[TMP24]], align 1
; CHECK-NEXT:    [[TMP26:%.*]] = add <4 x i16> [[WIDE_LOAD13]], [[WIDE_LOAD12]]
; CHECK-NEXT:    [[TMP27:%.*]] = getelementptr inbounds i16, ptr [[A]], i64 [[INDEX11]]
; CHECK-NEXT:    store <4 x i16> [[TMP26]], ptr [[TMP27]], align 1
; CHECK-NEXT:    [[INDEX_NEXT14]] = add nuw i64 [[INDEX11]], 4
; CHECK-NEXT:    [[TMP29:%.*]] = icmp eq i64 [[INDEX_NEXT14]], [[N_VEC10]]
; CHECK-NEXT:    br i1 [[TMP29]], label [[VEC_EPILOG_MIDDLE_BLOCK:%.*]], label [[VEC_EPILOG_VECTOR_BODY]], !llvm.loop [[LOOP6:![0-9]+]]
; CHECK:       vec.epilog.middle.block:
; CHECK-NEXT:    [[CMP_N15:%.*]] = icmp eq i64 [[ITERATIONS]], [[N_VEC10]]
; CHECK-NEXT:    br i1 [[CMP_N15]], label [[EXIT]], label [[VEC_EPILOG_SCALAR_PH]]
; CHECK:       vec.epilog.scalar.ph:
; CHECK-NEXT:    [[BC_RESUME_VAL:%.*]] = phi i64 [ [[N_VEC10]], [[VEC_EPILOG_MIDDLE_BLOCK]] ], [ [[N_VEC]], [[VEC_EPILOG_ITER_CHECK]] ], [ 0, [[ITER_CHECK:%.*]] ]
; CHECK-NEXT:    br label [[FOR_BODY:%.*]]
; CHECK:       for.body:
; CHECK-NEXT:    [[IV:%.*]] = phi i64 [ [[BC_RESUME_VAL]], [[VEC_EPILOG_SCALAR_PH]] ], [ [[IV_NEXT:%.*]], [[FOR_BODY]] ]
; CHECK-NEXT:    [[ARRAYIDX:%.*]] = getelementptr inbounds i16, ptr [[B]], i64 [[IV]]
; CHECK-NEXT:    [[TMP30:%.*]] = load i16, ptr [[ARRAYIDX]], align 1
; CHECK-NEXT:    [[ARRAYIDX2:%.*]] = getelementptr inbounds i16, ptr [[C]], i64 [[IV]]
; CHECK-NEXT:    [[TMP31:%.*]] = load i16, ptr [[ARRAYIDX2]], align 1
; CHECK-NEXT:    [[ADD:%.*]] = add i16 [[TMP31]], [[TMP30]]
; CHECK-NEXT:    [[ARRAYIDX6:%.*]] = getelementptr inbounds i16, ptr [[A]], i64 [[IV]]
; CHECK-NEXT:    store i16 [[ADD]], ptr [[ARRAYIDX6]], align 1
; CHECK-NEXT:    [[IV_NEXT]] = add nuw nsw i64 [[IV]], 1
; CHECK-NEXT:    [[EXITCOND_NOT:%.*]] = icmp eq i64 [[IV_NEXT]], [[ITERATIONS]]
; CHECK-NEXT:    br i1 [[EXITCOND_NOT]], label [[EXIT]], label [[FOR_BODY]], !llvm.loop [[LOOP7:![0-9]+]]
; CHECK:       exit:
; CHECK-NEXT:    ret void
;
entry:
  br label %for.body

for.body:
  %iv = phi i64 [ 0, %entry ], [ %iv.next, %for.body ]
  %arrayidx = getelementptr inbounds i16, ptr %B, i64 %iv
  %0 = load i16, ptr %arrayidx, align 1
  %arrayidx2 = getelementptr inbounds i16, ptr %C, i64 %iv
  %1 = load i16, ptr %arrayidx2, align 1
  %add = add i16 %1, %0
  %arrayidx6 = getelementptr inbounds i16, ptr %A, i64 %iv
  store i16 %add, ptr %arrayidx6, align 1
  %iv.next = add nuw nsw i64 %iv, 1
  %exitcond.not = icmp eq i64 %iv.next, %Iterations
  br i1 %exitcond.not, label %exit, label %for.body

exit:
  ret void
}

define void @add_i32(ptr noalias nocapture noundef writeonly %A, ptr nocapture noundef readonly %B, ptr nocapture noundef readonly %C, i64 noundef %Iterations) {
; CHECK-LABEL: @add_i32(
; CHECK-NEXT:  iter.check:
; CHECK-NEXT:    [[MIN_ITERS_CHECK:%.*]] = icmp ult i64 [[ITERATIONS:%.*]], 4
; CHECK-NEXT:    br i1 [[MIN_ITERS_CHECK]], label [[VEC_EPILOG_SCALAR_PH:%.*]], label [[VECTOR_MAIN_LOOP_ITER_CHECK:%.*]]
; CHECK:       vector.main.loop.iter.check:
; CHECK-NEXT:    [[MIN_ITERS_CHECK1:%.*]] = icmp ult i64 [[ITERATIONS]], 16
; CHECK-NEXT:    br i1 [[MIN_ITERS_CHECK1]], label [[VEC_EPILOG_PH:%.*]], label [[VECTOR_PH:%.*]]
; CHECK:       vector.ph:
; CHECK-NEXT:    [[N_MOD_VF:%.*]] = urem i64 [[ITERATIONS]], 16
; CHECK-NEXT:    [[N_VEC:%.*]] = sub i64 [[ITERATIONS]], [[N_MOD_VF]]
; CHECK-NEXT:    br label [[VECTOR_BODY:%.*]]
; CHECK:       vector.body:
; CHECK-NEXT:    [[INDEX:%.*]] = phi i64 [ 0, [[VECTOR_PH]] ], [ [[INDEX_NEXT:%.*]], [[VECTOR_BODY]] ]
; CHECK-NEXT:    [[TMP1:%.*]] = getelementptr inbounds i32, ptr [[B:%.*]], i64 [[INDEX]]
; CHECK-NEXT:    [[TMP3:%.*]] = getelementptr inbounds i32, ptr [[TMP1]], i32 4
; CHECK-NEXT:    [[TMP4:%.*]] = getelementptr inbounds i32, ptr [[TMP1]], i32 8
; CHECK-NEXT:    [[TMP5:%.*]] = getelementptr inbounds i32, ptr [[TMP1]], i32 12
; CHECK-NEXT:    [[WIDE_LOAD:%.*]] = load <4 x i32>, ptr [[TMP1]], align 1
; CHECK-NEXT:    [[WIDE_LOAD2:%.*]] = load <4 x i32>, ptr [[TMP3]], align 1
; CHECK-NEXT:    [[WIDE_LOAD3:%.*]] = load <4 x i32>, ptr [[TMP4]], align 1
; CHECK-NEXT:    [[WIDE_LOAD4:%.*]] = load <4 x i32>, ptr [[TMP5]], align 1
; CHECK-NEXT:    [[TMP6:%.*]] = getelementptr inbounds i32, ptr [[C:%.*]], i64 [[INDEX]]
; CHECK-NEXT:    [[TMP8:%.*]] = getelementptr inbounds i32, ptr [[TMP6]], i32 4
; CHECK-NEXT:    [[TMP9:%.*]] = getelementptr inbounds i32, ptr [[TMP6]], i32 8
; CHECK-NEXT:    [[TMP10:%.*]] = getelementptr inbounds i32, ptr [[TMP6]], i32 12
; CHECK-NEXT:    [[WIDE_LOAD5:%.*]] = load <4 x i32>, ptr [[TMP6]], align 1
; CHECK-NEXT:    [[WIDE_LOAD6:%.*]] = load <4 x i32>, ptr [[TMP8]], align 1
; CHECK-NEXT:    [[WIDE_LOAD7:%.*]] = load <4 x i32>, ptr [[TMP9]], align 1
; CHECK-NEXT:    [[WIDE_LOAD8:%.*]] = load <4 x i32>, ptr [[TMP10]], align 1
; CHECK-NEXT:    [[TMP11:%.*]] = add <4 x i32> [[WIDE_LOAD5]], [[WIDE_LOAD]]
; CHECK-NEXT:    [[TMP12:%.*]] = add <4 x i32> [[WIDE_LOAD6]], [[WIDE_LOAD2]]
; CHECK-NEXT:    [[TMP13:%.*]] = add <4 x i32> [[WIDE_LOAD7]], [[WIDE_LOAD3]]
; CHECK-NEXT:    [[TMP14:%.*]] = add <4 x i32> [[WIDE_LOAD8]], [[WIDE_LOAD4]]
; CHECK-NEXT:    [[TMP15:%.*]] = getelementptr inbounds i32, ptr [[A:%.*]], i64 [[INDEX]]
; CHECK-NEXT:    [[TMP17:%.*]] = getelementptr inbounds i32, ptr [[TMP15]], i32 4
; CHECK-NEXT:    [[TMP18:%.*]] = getelementptr inbounds i32, ptr [[TMP15]], i32 8
; CHECK-NEXT:    [[TMP19:%.*]] = getelementptr inbounds i32, ptr [[TMP15]], i32 12
; CHECK-NEXT:    store <4 x i32> [[TMP11]], ptr [[TMP15]], align 1
; CHECK-NEXT:    store <4 x i32> [[TMP12]], ptr [[TMP17]], align 1
; CHECK-NEXT:    store <4 x i32> [[TMP13]], ptr [[TMP18]], align 1
; CHECK-NEXT:    store <4 x i32> [[TMP14]], ptr [[TMP19]], align 1
; CHECK-NEXT:    [[INDEX_NEXT]] = add nuw i64 [[INDEX]], 16
; CHECK-NEXT:    [[TMP20:%.*]] = icmp eq i64 [[INDEX_NEXT]], [[N_VEC]]
; CHECK-NEXT:    br i1 [[TMP20]], label [[MIDDLE_BLOCK:%.*]], label [[VECTOR_BODY]], !llvm.loop [[LOOP8:![0-9]+]]
; CHECK:       middle.block:
; CHECK-NEXT:    [[CMP_N:%.*]] = icmp eq i64 [[ITERATIONS]], [[N_VEC]]
; CHECK-NEXT:    br i1 [[CMP_N]], label [[EXIT:%.*]], label [[VEC_EPILOG_ITER_CHECK:%.*]]
; CHECK:       vec.epilog.iter.check:
; CHECK-NEXT:    [[N_VEC_REMAINING:%.*]] = sub i64 [[ITERATIONS]], [[N_VEC]]
; CHECK-NEXT:    [[MIN_EPILOG_ITERS_CHECK:%.*]] = icmp ult i64 [[N_VEC_REMAINING]], 4
; CHECK-NEXT:    br i1 [[MIN_EPILOG_ITERS_CHECK]], label [[VEC_EPILOG_SCALAR_PH]], label [[VEC_EPILOG_PH]]
; CHECK:       vec.epilog.ph:
; CHECK-NEXT:    [[VEC_EPILOG_RESUME_VAL:%.*]] = phi i64 [ [[N_VEC]], [[VEC_EPILOG_ITER_CHECK]] ], [ 0, [[VECTOR_MAIN_LOOP_ITER_CHECK]] ]
; CHECK-NEXT:    [[N_MOD_VF9:%.*]] = urem i64 [[ITERATIONS]], 4
; CHECK-NEXT:    [[N_VEC10:%.*]] = sub i64 [[ITERATIONS]], [[N_MOD_VF9]]
; CHECK-NEXT:    br label [[VEC_EPILOG_VECTOR_BODY:%.*]]
; CHECK:       vec.epilog.vector.body:
; CHECK-NEXT:    [[INDEX11:%.*]] = phi i64 [ [[VEC_EPILOG_RESUME_VAL]], [[VEC_EPILOG_PH]] ], [ [[INDEX_NEXT14:%.*]], [[VEC_EPILOG_VECTOR_BODY]] ]
; CHECK-NEXT:    [[TMP22:%.*]] = getelementptr inbounds i32, ptr [[B]], i64 [[INDEX11]]
; CHECK-NEXT:    [[WIDE_LOAD12:%.*]] = load <4 x i32>, ptr [[TMP22]], align 1
; CHECK-NEXT:    [[TMP24:%.*]] = getelementptr inbounds i32, ptr [[C]], i64 [[INDEX11]]
; CHECK-NEXT:    [[WIDE_LOAD13:%.*]] = load <4 x i32>, ptr [[TMP24]], align 1
; CHECK-NEXT:    [[TMP26:%.*]] = add <4 x i32> [[WIDE_LOAD13]], [[WIDE_LOAD12]]
; CHECK-NEXT:    [[TMP27:%.*]] = getelementptr inbounds i32, ptr [[A]], i64 [[INDEX11]]
; CHECK-NEXT:    store <4 x i32> [[TMP26]], ptr [[TMP27]], align 1
; CHECK-NEXT:    [[INDEX_NEXT14]] = add nuw i64 [[INDEX11]], 4
; CHECK-NEXT:    [[TMP29:%.*]] = icmp eq i64 [[INDEX_NEXT14]], [[N_VEC10]]
; CHECK-NEXT:    br i1 [[TMP29]], label [[VEC_EPILOG_MIDDLE_BLOCK:%.*]], label [[VEC_EPILOG_VECTOR_BODY]], !llvm.loop [[LOOP9:![0-9]+]]
; CHECK:       vec.epilog.middle.block:
; CHECK-NEXT:    [[CMP_N15:%.*]] = icmp eq i64 [[ITERATIONS]], [[N_VEC10]]
; CHECK-NEXT:    br i1 [[CMP_N15]], label [[EXIT]], label [[VEC_EPILOG_SCALAR_PH]]
; CHECK:       vec.epilog.scalar.ph:
; CHECK-NEXT:    [[BC_RESUME_VAL:%.*]] = phi i64 [ [[N_VEC10]], [[VEC_EPILOG_MIDDLE_BLOCK]] ], [ [[N_VEC]], [[VEC_EPILOG_ITER_CHECK]] ], [ 0, [[ITER_CHECK:%.*]] ]
; CHECK-NEXT:    br label [[FOR_BODY:%.*]]
; CHECK:       for.body:
; CHECK-NEXT:    [[IV:%.*]] = phi i64 [ [[BC_RESUME_VAL]], [[VEC_EPILOG_SCALAR_PH]] ], [ [[IV_NEXT:%.*]], [[FOR_BODY]] ]
; CHECK-NEXT:    [[ARRAYIDX:%.*]] = getelementptr inbounds i32, ptr [[B]], i64 [[IV]]
; CHECK-NEXT:    [[TMP30:%.*]] = load i32, ptr [[ARRAYIDX]], align 1
; CHECK-NEXT:    [[ARRAYIDX2:%.*]] = getelementptr inbounds i32, ptr [[C]], i64 [[IV]]
; CHECK-NEXT:    [[TMP31:%.*]] = load i32, ptr [[ARRAYIDX2]], align 1
; CHECK-NEXT:    [[ADD:%.*]] = add i32 [[TMP31]], [[TMP30]]
; CHECK-NEXT:    [[ARRAYIDX6:%.*]] = getelementptr inbounds i32, ptr [[A]], i64 [[IV]]
; CHECK-NEXT:    store i32 [[ADD]], ptr [[ARRAYIDX6]], align 1
; CHECK-NEXT:    [[IV_NEXT]] = add nuw nsw i64 [[IV]], 1
; CHECK-NEXT:    [[EXITCOND_NOT:%.*]] = icmp eq i64 [[IV_NEXT]], [[ITERATIONS]]
; CHECK-NEXT:    br i1 [[EXITCOND_NOT]], label [[EXIT]], label [[FOR_BODY]], !llvm.loop [[LOOP10:![0-9]+]]
; CHECK:       exit:
; CHECK-NEXT:    ret void
;
entry:
  br label %for.body

for.body:
  %iv = phi i64 [ 0, %entry ], [ %iv.next, %for.body ]
  %arrayidx = getelementptr inbounds i32, ptr %B, i64 %iv
  %0 = load i32, ptr %arrayidx, align 1
  %arrayidx2 = getelementptr inbounds i32, ptr %C, i64 %iv
  %1 = load i32, ptr %arrayidx2, align 1
  %add = add i32 %1, %0
  %arrayidx6 = getelementptr inbounds i32, ptr %A, i64 %iv
  store i32 %add, ptr %arrayidx6, align 1
  %iv.next = add nuw nsw i64 %iv, 1
  %exitcond.not = icmp eq i64 %iv.next, %Iterations
  br i1 %exitcond.not, label %exit, label %for.body

exit:
  ret void
}
