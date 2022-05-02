# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

add_llvm_library(sollCodeGen
                 BackendUtil.cpp
                 CGExpr.cpp
                 CodeGenAction.cpp
                 CodeGenFunction.cpp
                 CodeGenModule.cpp
                 LoweringInteger.cpp
                 ModuleBuilder.cpp
                 ABICodec.cpp
                 ExprEmitter.cpp

                 LINK_LIBS

                 crypto3::hash

                 sollAST
                 sollBasic
                 sollFrontend

                 lldWasm
                 lldCommon

                 LINK_COMPONENTS
                 Analysis
                 BitWriter
                 CodeGen
                 Core
                 ipo
                 MC
                 Passes
                 Support
                 Target
                 TransformUtils
                 )

if(SOLL_ENABLE_EVM)
    add_definitions(-DENABLE_EVM_BACKEND)
endif()
