#pragma once

#include <memory>

namespace soll {

class Decl;
class InheritanceSpecifier;
class FunctionDecl;
class ModifierInvocation;
class ParamList;
class VarDecl;
class Stmt;
class Block;
class Expr;
class Type;

using DeclPtr = std::unique_ptr<Decl>;
using VarDeclPtr = std::unique_ptr<VarDecl>;
using StmtPtr = std::unique_ptr<Stmt>;
using ExprPtr = std::unique_ptr<Expr>;
using TypePtr = std::unique_ptr<Type>;

} // namespace soll