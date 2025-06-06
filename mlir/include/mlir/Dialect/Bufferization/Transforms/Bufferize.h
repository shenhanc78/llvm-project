//===- Bufferize.h - Bufferization Utilities --------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// We use the term "bufferize" to mean conversion from tensor types to
// memref types.
//
// Generally speaking, for each op that operates on tensor types, the
// `BufferizableOpInterface` needs to be implemented. This file contains the
// bufferization driver that is responsible for bufferizing the ops in the right
// order, etc.
//
//===----------------------------------------------------------------------===//

#ifndef MLIR_DIALECT_BUFFERIZATION_TRANSFORMS_BUFFERIZE_H
#define MLIR_DIALECT_BUFFERIZATION_TRANSFORMS_BUFFERIZE_H

#include "mlir/Transforms/DialectConversion.h"

namespace mlir {
namespace bufferization {

class AnalysisState;
struct BufferizationOptions;
class BufferizationState;
class OpFilter;

/// Bufferization statistics for debugging. These can be printed after running
/// the OneShotBufferizePass with `-mlir-pass-statistics`. See the pass
/// definition for more details.
struct BufferizationStatistics {
  int64_t numBufferAlloc = 0;
  int64_t numBufferDealloc = 0;
  int64_t numTensorInPlace = 0;
  int64_t numTensorOutOfPlace = 0;
};

/// Bufferize `op` and its nested ops that implement `BufferizableOpInterface`.
///
/// Note: This function does not resolve read-after-write conflicts. Use this
/// function only if it is guaranteed that the input IR can bufferize without
/// additional buffer copies or set "options.copyBeforeWrite = true". The
/// general bufferization entry point is `runOneShotBufferize`.
LogicalResult bufferizeOp(Operation *op, const BufferizationOptions &options,
                          BufferizationState &bufferizationState,
                          BufferizationStatistics *statistics = nullptr);

/// Bufferize the signature of `block` and its callers (i.e., ops that have the
/// given block as a successor). All block argument types are changed to memref
/// types. All corresponding operands of all callers  are wrapped in
/// bufferization.to_buffer ops. All uses of bufferized tensor block arguments
/// are wrapped in bufferization.to_tensor ops.
///
/// It is expected that all callers implement the `BranchOpInterface`.
/// Otherwise, this function will fail. The `BranchOpInterface` is used to query
/// the range of operands that are forwarded to this block.
///
/// It is expected that the parent op of this block implements the
/// `BufferizableOpInterface`. The buffer types of tensor block arguments are
/// computed with `BufferizableOpIntercace::getBufferType`.
LogicalResult bufferizeBlockSignature(Block *block, RewriterBase &rewriter,
                                      const BufferizationOptions &options,
                                      BufferizationState &state);

} // namespace bufferization
} // namespace mlir

#endif // MLIR_DIALECT_BUFFERIZATION_TRANSFORMS_BUFFERIZE_H
