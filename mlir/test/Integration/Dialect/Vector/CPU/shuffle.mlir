// RUN: mlir-opt %s -test-lower-to-llvm  | \
// RUN: mlir-runner -e entry -entry-point-result=void  \
// RUN:   -shared-libs=%mlir_c_runner_utils | \
// RUN: FileCheck %s

func.func @entry() {
  %f1 = arith.constant 1.0: f32
  %f2 = arith.constant 2.0: f32
  %v1 = vector.broadcast %f1 : f32 to vector<2x4xf32>
  %v2 = vector.broadcast %f2 : f32 to vector<2x4xf32>
  vector.print %v1 : vector<2x4xf32>
  vector.print %v2 : vector<2x4xf32>
  //
  // test vectors:
  //
  // CHECK: ( ( 1, 1, 1, 1 ), ( 1, 1, 1, 1 ) )
  // CHECK: ( ( 2, 2, 2, 2 ), ( 2, 2, 2, 2 ) )

  %v3 = vector.shuffle %v1, %v2 [3, 1, 2] : vector<2x4xf32>, vector<2x4xf32>
  vector.print %v3 : vector<3x4xf32>
  // CHECK: ( ( 2, 2, 2, 2 ), ( 1, 1, 1, 1 ), ( 2, 2, 2, 2 ) )

  return
}
