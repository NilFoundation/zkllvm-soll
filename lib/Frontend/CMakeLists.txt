# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
add_llvm_library(sollFrontend
                 ASTConsumers/ABIPrinter.cpp
                 ASTConsumers/ASTPrinter.cpp
                 ASTConsumers/FuncSigPrinter.cpp
                 CompilerInstance.cpp
                 CompilerInvocation.cpp
                 DiagnosticRenderer.cpp
                 FrontendAction.cpp
                 FrontendActions.cpp
                 TextDiagnostic.cpp
                 TextDiagnosticPrinter.cpp

                 LINK_LIBS
                 sollBasic
                 sollAST
                 sollLex
                 sollParse
                 sollSema

                 crypto3::hash

                 LINK_COMPONENTS
                 support
                 )
