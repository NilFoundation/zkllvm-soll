# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
add_llvm_library(sollAST
                 ASTContext.cpp
                 Decl.cpp
                 DeclAccept.cpp
                 DeclAsm.cpp
                 DeclVisitor.cpp
                 DeclYul.cpp
                 Expr.cpp
                 ExprAsm.cpp
                 Stmt.cpp
                 StmtAccept.cpp
                 StmtAsm.cpp
                 StmtVisitor.cpp
                 Type.cpp

                 LINK_COMPONENTS
                 Support

                 LINK_LIBS
                 crypto3::block
                 crypto3::codec
                 crypto3::hash
                 )