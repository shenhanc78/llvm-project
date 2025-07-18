//===- InferTypeOpInterface.td - Infer Type interfaces -----*- tablegen -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file contains a set of interfaces that can be used to define information
// related to type inference.
//
// This interface is also used by ODS to create builders for operations that
// do not require result type to be specified. Including this interface in
// dialect op definitions is sufficient to result in such builders being
// automatically generated for trivially buildable result types.
//
//===----------------------------------------------------------------------===//

#ifndef MLIR_INFERTYPEOPINTERFACE
#define MLIR_INFERTYPEOPINTERFACE

include "mlir/IR/OpBase.td"

// OpInterface to compute the return type of an operation. The arguments match
// those in Operation::create with the exception that the location is optional
// (if no location is provided, then the method will not emit an error on
// mismatch).
def InferTypeOpInterface : OpInterface<"InferTypeOpInterface"> {
  let description = [{
    Interface to infer the return types for an operation that could be used
    during op construction, verification or type inference.
  }];
  let cppNamespace = "::mlir";

  let methods = [
    StaticInterfaceMethod<
      /*desc=*/[{Infer the return types that an op would generate.

      The method takes an optional location which, if set, will be used to
      report errors on. The operands and attributes correspond to those with
      which an Operation would be created (e.g., as used in Operation::create)
      and the regions of the op. Be aware that this method is supposed to be
      called with valid arguments, e.g., operands are verified, or it may result
      in an undefined behavior.

      The inferred result types may be less precise than what may be specified
      directly or produced by refinement, but are required to be compatible
      (as defined by the op's compatibility function).
      }],
      /*retTy=*/"::llvm::LogicalResult",
      /*methodName=*/"inferReturnTypes",
      /*args=*/(ins "::mlir::MLIRContext *":$context,
                    "::std::optional<::mlir::Location>":$location,
                    "::mlir::ValueRange":$operands,
                    "::mlir::DictionaryAttr":$attributes,
                    "::mlir::OpaqueProperties":$properties,
                    "::mlir::RegionRange":$regions,
                    "::llvm::SmallVectorImpl<::mlir::Type>&":$inferredReturnTypes)
    >,
    StaticInterfaceMethod<
      /*desc=*/[{Refine the return types that an op would generate.

      This method computes the return types as `inferReturnTypes` does but
      additionally takes the existing result types as input. The existing
      result types can be checked as part of inference to provide more
      op-specific error messages as well as part of inference to merge
      additional information, attributes, during inference. It is called during
      verification for ops implementing this trait with default behavior
      reporting mismatch with current and inferred types printed.

      The operands and attributes correspond to those with which an Operation
      would be created (e.g., as used in Operation::create) and the regions of
      the op. The method takes an optional location which, if set, will be used
      to report errors on.

      The return types may be elided or specific elements be null for elements
      that should just be returned but not verified.

      This method may be called from within different stages of IR verification,
      implementations should not assume the arguments to represent fully valid
      IR and are responsible for checking inputs for validity to the degree
      necessary to perform the return type inference.
      }],
      /*retTy=*/"::llvm::LogicalResult",
      /*methodName=*/"refineReturnTypes",
      /*args=*/(ins "::mlir::MLIRContext *":$context,
                    "::std::optional<::mlir::Location>":$location,
                    "::mlir::ValueRange":$operands,
                    "::mlir::DictionaryAttr":$attributes,
                    "::mlir::OpaqueProperties":$properties,
                    "::mlir::RegionRange":$regions,
                    "::llvm::SmallVectorImpl<::mlir::Type>&":$returnTypes),
      /*methodBody=*/[{}],
      /*defaultImplementation=*/[{
          llvm::SmallVector<Type, 4> inferredReturnTypes;
          if (failed(ConcreteOp::inferReturnTypes(context, location, operands,
                                                  attributes, properties, regions,
                                                  inferredReturnTypes)))
            return failure();
          if (!ConcreteOp::isCompatibleReturnTypes(inferredReturnTypes,
                                                   returnTypes)) {
            return emitOptionalError(
                location, "'", ConcreteOp::getOperationName(),
                "' op inferred type(s) ", inferredReturnTypes,
                " are incompatible with return type(s) of operation ",
                returnTypes);
          }
          return success();
      }]
    >,
    StaticInterfaceMethod<
      /*desc=*/"Returns whether two type ranges are compatible result types.",
      /*retTy=*/"bool",
      /*methodName=*/"isCompatibleReturnTypes",
      /*args=*/(ins "::mlir::TypeRange":$lhs, "::mlir::TypeRange":$rhs),
      /*methodBody=*/[{
        return ConcreteOp::isCompatibleReturnTypes(lhs, rhs);
      }],
      /*defaultImplementation=*/[{
        /// Returns whether two arrays are equal as strongest check for
        /// compatibility by default.
        return lhs == rhs;
      }]
    >,
  ];

  // Inferring result types may need to access the region operations.
  let verifyWithRegions = 1;
  let verify = [{
    return detail::verifyInferredResultTypes($_op);
  }];
}

def InferShapedTypeOpInterface : OpInterface<"InferShapedTypeOpInterface"> {
  let description = [{
    Interface to infer the components of a ShapedType returned by an operation
    that could be used during op construction, verification or shape inference.

    The components consists of element type, shape and raw attribute.
  }];
  let cppNamespace = "::mlir";

  let methods = [
    StaticInterfaceMethod<
      /*desc=*/[{Infer the components of return type of shape containter.

      The method takes an optional location which, if set, will be used to
      report errors on. The operands and attributes correspond to those with
      which an Operation would be created (e.g., as used in Operation::create)
      and the regions of the op.

      Unknown (e.g., unranked) shape and nullptrs for element type and attribute
      may be returned by this function while returning success. E.g., partial
      population of components is not error condition.

      Because this method can be called from within different stages of IR
      verification, implementations should not assume the arguments to
      represent fully valid IR and are responsible for checking inputs for
      validity to the degree necessary to perform the return type inference.
      }],
      /*retTy=*/"::llvm::LogicalResult",
      /*methodName=*/"inferReturnTypeComponents",
      /*args=*/(ins "::mlir::MLIRContext*":$context,
                    "::std::optional<::mlir::Location>":$location,
                    "::mlir::ValueShapeRange":$operands,
                    "::mlir::DictionaryAttr":$attributes,
                    "::mlir::OpaqueProperties":$properties,
                    "::mlir::RegionRange":$regions,
                    "::llvm::SmallVectorImpl<::mlir::ShapedTypeComponents>&":
                      $inferredReturnShapes),
      /*methodBody=*/[{}],
      /*defaultImplementation=*/[{ return ::mlir::failure(); }]
    >,
    InterfaceMethod<
      /*desc=*/[{Reify the shape computation for the operation.

      Insert operations using the given OpBuilder that computes the
      result shape. This interface is supposed to be workable during dialect
      conversion (e.g. convert from tensor world to buffer world),
      where `getOperand` may be invalid. For example, some ops (e.g.
      dynamic_reshape(input, target_shape)) may depend on their operands
      to calculate the result shape. When the `matchAndRewrite ` method
      of a conversion pattern is called, the operands of the op to convert
      may have been converted into other types, which makes it invalid to
      call the `getOperand` method of such op directly inside the
      conversion pattern.  To solve this problem, this interface follows
      the design of the conversion pattern, that is, accepting passed in
      operands to avoid calling `getOperand` directly inside the interface
      implementation.
      }],
      /*retTy=*/"::llvm::LogicalResult",
      /*methodName=*/"reifyReturnTypeShapes",
      /*args=*/(ins "::mlir::OpBuilder&":$builder,
          "::mlir::ValueRange":$operands,
          "::llvm::SmallVectorImpl<::mlir::Value> &":$reifiedReturnShapes),
      /*methodBody=*/[{}],
      /*defaultImplementation=*/[{ return ::mlir::failure(); }]
    >
  ];
}

// Convenient trait to define a wrapper to inferReturnTypes that passes in the
// Op Adaptor directly
class InferTypeOpAdaptorBase<code additionalDecls = [{}]> : TraitList<
  [
    // Op implements infer type op interface.
    DeclareOpInterfaceMethods<InferTypeOpInterface>,
    NativeOpTrait<
      /*name=*/"InferTypeOpAdaptor",
      /*traits=*/[],
      /*extraOpDeclaration=*/[{
        static ::llvm::LogicalResult
        inferReturnTypes(::mlir::MLIRContext *context,
                                std::optional<::mlir::Location> location,
                                Adaptor adaptor,
                                ::llvm::SmallVectorImpl<::mlir::Type> &inferredReturnTypes);
      }] # additionalDecls,
      /*extraOpDefinition=*/[{
        ::llvm::LogicalResult
        $cppClass::inferReturnTypes(::mlir::MLIRContext *context,
                          std::optional<::mlir::Location> location,
                          ::mlir::ValueRange operands, ::mlir::DictionaryAttr attributes,
                          ::mlir::OpaqueProperties properties, ::mlir::RegionRange regions,
                          ::llvm::SmallVectorImpl<::mlir::Type> &inferredReturnTypes) {
          $cppClass::Adaptor adaptor(operands, attributes, properties, regions);
          return $cppClass::inferReturnTypes(context,
            location, adaptor, inferredReturnTypes);
        }
      }]
    >
  ]>;

def InferTypeOpAdaptor : InferTypeOpAdaptorBase;
def InferTypeOpAdaptorWithIsCompatible : InferTypeOpAdaptorBase<
  [{
    static bool isCompatibleReturnTypes(::mlir::TypeRange l, ::mlir::TypeRange r);
  }]
>;

// Convenient trait to define a wrapper to inferReturnTypeComponents that passes
// in the Op Adaptor directly. Only uses the current types of the operands.
class InferShapedTypeOpAdaptorBase<list<string> overridenMethods = []> : TraitList<
  [
    // Op implements infer type op interface.
    DeclareOpInterfaceMethods<InferShapedTypeOpInterface, overridenMethods>,
    NativeOpTrait<
      /*name=*/"InferShapedTypeOpAdaptor",
      /*traits=*/[],
      /*extraOpDeclaration=*/[{
        static ::llvm::LogicalResult
        inferReturnTypeComponents(::mlir::MLIRContext *context,
                                std::optional<::mlir::Location> location,
                                Adaptor adaptor,
                                ::llvm::SmallVectorImpl<::mlir::ShapedTypeComponents> &inferredReturnShapes);
      }],
      /*extraOpDefinition=*/[{
        ::llvm::LogicalResult
        $cppClass::inferReturnTypeComponents(::mlir::MLIRContext *context,
                          std::optional<::mlir::Location> location,
                          ::mlir::ValueShapeRange operands, ::mlir::DictionaryAttr attributes,
                          ::mlir::OpaqueProperties properties, ::mlir::RegionRange regions,
                          ::llvm::SmallVectorImpl<::mlir::ShapedTypeComponents> &inferredReturnShapes) {
          $cppClass::Adaptor adaptor(operands, attributes, properties, regions);
          return $cppClass::inferReturnTypeComponents(context,
            location, adaptor, inferredReturnShapes);
        }
      }]
    >
  ]>;

def InferShapedTypeOpAdaptor : InferShapedTypeOpAdaptorBase<[
  "inferReturnTypeComponents"]>;
def InferShapedTypeOpAdaptorWithReify : InferShapedTypeOpAdaptorBase<[
  "inferReturnTypeComponents", "reifyReturnTypeShapes"]>;

// Convenience class grouping together type and shaped type op interfaces for
// ops that have tensor return types.
class InferTensorTypeBase<list<string> overridenMethods = []> : TraitList<
  [
    // Op implements infer type op interface.
    DeclareOpInterfaceMethods<InferTypeOpInterface>,
    // The op will have methods implementing the ShapedType type inference
    // interface.
    DeclareOpInterfaceMethods<InferShapedTypeOpInterface, overridenMethods>,
    // The op produces tensors and will use the ShapedType type infer interface
    // along with knowledge that it is producing Tensors to infer the type.
    NativeOpTrait<
      /*name=*/"InferTensorType",
      /*traits=*/[],
      /*extraOpDeclaration=*/[{}],
      /*extraOpDefinition=*/[{
        ::llvm::LogicalResult
        $cppClass::inferReturnTypes(::mlir::MLIRContext *context,
                          std::optional<::mlir::Location> location,
                          ::mlir::ValueRange operands, ::mlir::DictionaryAttr attributes,
                          ::mlir::OpaqueProperties properties, ::mlir::RegionRange regions,
                          ::llvm::SmallVectorImpl<::mlir::Type> &inferredReturnTypes) {
          ::llvm::SmallVector<::mlir::ShapedTypeComponents, 2> retComponents;
          if (failed($cppClass::inferReturnTypeComponents(context, location,
                                    operands, attributes, properties, regions,
                                    retComponents)))
            return failure();
          return ::mlir::detail::inferReturnTensorTypes(retComponents,
                                    inferredReturnTypes);
        }
      }]
    >
  ]>;

def InferTensorType : InferTensorTypeBase<["inferReturnTypeComponents"]>;
def InferTensorTypeWithReify: InferTensorTypeBase<[
    "inferReturnTypeComponents", "reifyReturnTypeShapes"]>;

// Convenience class grouping together type and shaped type op interfaces for
// ops that have tensor return types.
class InferTensorTypeAdaptorBase<list<string> overridenMethods = []> : TraitList<
  [
    // Op implements infer type op interface.
    DeclareOpInterfaceMethods<InferTypeOpInterface>,
    // The op will have methods implementing the ShapedType type inference
    // interface.
    InferShapedTypeOpAdaptorBase<overridenMethods>,
    // The op produces tensors and will use the ShapedType type infer interface
    // along with knowledge that it is producing Tensors to infer the type.
    NativeOpTrait<
      /*name=*/"InferTensorType",
      /*traits=*/[],
      /*extraOpDeclaration=*/[{}],
      /*extraOpDefinition=*/[{
        LogicalResult
        $cppClass::inferReturnTypes(::mlir::MLIRContext *context,
                          std::optional<::mlir::Location> location,
                          ::mlir::ValueRange operands, ::mlir::DictionaryAttr attributes,
                          ::mlir::OpaqueProperties properties, ::mlir::RegionRange regions,
                          ::llvm::SmallVectorImpl<::mlir::Type> &inferredReturnTypes) {
          SmallVector<ShapedTypeComponents, 2> retComponents;
          if (failed($cppClass::inferReturnTypeComponents(context, location,
                                    operands, attributes, properties, regions,
                                    retComponents)))
            return failure();
          return ::mlir::detail::inferReturnTensorTypes(retComponents,
                                    inferredReturnTypes);
        }
      }]
    >
  ]>;

def InferTensorTypeAdaptor : InferTensorTypeAdaptorBase<["inferReturnTypeComponents"]>;
def InferTensorTypeAdaptorWithReify: InferTensorTypeAdaptorBase<[
    "inferReturnTypeComponents", "reifyReturnTypeShapes"]>;

def ReifyRankedShapedTypeOpInterface :
    OpInterface<"ReifyRankedShapedTypeOpInterface"> {
  let description = [{
    Interface to compute the shape of the result of an operation when
    the result is a ranked shape type, i.e. `RankedTensorType` or
    `MemRefType`.
  }];
  let cppNamespace = "::mlir";

  let methods = [
    InterfaceMethod<
      /*desc=*/[{
        Reify the shape of the result of an operation (typically in terms of the
        shape of its operands).

        `reifiedReturnShapes` is populated with one vector per op result. Each
        of those vectors contains an OpFoldResult for each dimension of the
        shaped type. The given builder may be used to insert ops that compute
        result shapes.

        If the shape of a particular result cannot be computed it must be empty.
      }],
      /*retTy=*/"::llvm::LogicalResult",
      /*methodName=*/"reifyResultShapes",
      /*args=*/(ins "::mlir::OpBuilder &":$builder,
        "::mlir::ReifiedRankedShapedTypeDims &":$reifiedReturnShapes)
    >
  ];
}

// Op has the same operand and result type.
// TODO: Change from hard coded to utilizing type inference trait.
def SameOperandsAndResultType : NativeOpTrait<"SameOperandsAndResultType">;

// Op has the same ranks for all operands and results types, if known.
def SameOperandsAndResultRank : NativeOpTrait<"SameOperandsAndResultRank">;

#endif // MLIR_INFERTYPEOPINTERFACE
