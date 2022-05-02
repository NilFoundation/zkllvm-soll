# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
list(APPEND LLVM_LINK_COMPONENTS
     AllTargetsCodeGens
     AllTargetsAsmParsers
     AllTargetsDescs
     AllTargetsInfos
     )

add_llvm_executable(soll main.cpp)

target_link_libraries(soll PRIVATE

                      crypto3::block
                      crypto3::codec
                      crypto3::hash

                      LLVMSupport

                      sollBasic
                      sollFrontend
                      sollFrontendTool

                      Threads::Threads
                      )
