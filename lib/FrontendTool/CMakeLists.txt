# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
add_llvm_library(sollFrontendTool
                 ExecuteCompilerInvocation.cpp

                 LINK_LIBS

                 crypto3::hash

                 sollFrontend
                 sollCodeGen
                 )
