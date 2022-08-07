# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
cmake_minimum_required(VERSION 3.11)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()
#set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
#set(CMAKE_LINKER_FLAGS_DEBUG "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")

# Enable assertions by default, so release builds work the same as debug builds.
# To disable assertions, pass `-DCMAKE_CXX_FLAGS=-DNDEBUG`.
string(REPLACE "-DNDEBUG" "" CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")
string(REPLACE "-DNDEBUG" "" CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}")
string(REPLACE "-DNDEBUG" "" CMAKE_CXX_FLAGS_MINSIZEREL "${CMAKE_CXX_FLAGS_MINSIZEREL}")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/utils/unittests/cmake")
set(SOLL_VERSION_MAJOR 0)
set(SOLL_VERSION_MINOR 1)
set(SOLL_VERSION_PATCH 1)
set(SOLL_VERSION_STRING
    "${SOLL_VERSION_MAJOR}.${SOLL_VERSION_MINOR}.${SOLL_VERSION_PATCH}")

project(SOLL
        VERSION ${SOLL_VERSION_MAJOR}.${SOLL_VERSION_MINOR}.${SOLL_VERSION_PATCH}
        LANGUAGES CXX)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/include/soll/Config/Config.h.cmake
               ${CMAKE_CURRENT_BINARY_DIR}/include/soll/Config/Config.h)

if(SOLL_BUILT_STANDALONE)
    # Rely on llvm-config.
    set(LLVM_CONFIG_OUTPUT)
    if(LLVM_CONFIG)
        set(LLVM_CONFIG_FOUND 1)
        message(STATUS "Found LLVM_CONFIG as ${LLVM_CONFIG}")
        message(DEPRECATION "Using llvm-config to detect the LLVM installation is \
          deprecated.  The installed cmake files should be used \
          instead.  CMake should be able to detect your LLVM install \
          automatically, but you can also use LLVM_DIR to specify \
          the path containing LLVMConfig.cmake.")
        set(CONFIG_COMMAND ${LLVM_CONFIG}
            "--includedir"
            "--prefix"
            "--src-root"
            "--cmakedir"
            "--bindir"
            "--libdir"
            "--assertion-mode"
            )
        execute_process(
                COMMAND ${CONFIG_COMMAND}
                RESULT_VARIABLE HAD_ERROR
                OUTPUT_VARIABLE LLVM_CONFIG_OUTPUT
        )
        if(NOT HAD_ERROR)
            string(REGEX REPLACE
                   "[ \t]*[\r\n]+[ \t]*" ";"
                   LLVM_CONFIG_OUTPUT ${LLVM_CONFIG_OUTPUT})
        else()
            string(REPLACE ";" " " CONFIG_COMMAND_STR "${CONFIG_COMMAND}")
            message(STATUS "${CONFIG_COMMAND_STR}")
            message(FATAL_ERROR "llvm-config failed with status ${HAD_ERROR}")
        endif()

        list(GET LLVM_CONFIG_OUTPUT 0 MAIN_INCLUDE_DIR)
        list(GET LLVM_CONFIG_OUTPUT 1 LLVM_OBJ_ROOT)
        list(GET LLVM_CONFIG_OUTPUT 2 MAIN_SRC_DIR)
        list(GET LLVM_CONFIG_OUTPUT 3 LLVM_CONFIG_CMAKE_DIR)
        list(GET LLVM_CONFIG_OUTPUT 4 TOOLS_BINARY_DIR)
        list(GET LLVM_CONFIG_OUTPUT 5 LIBRARY_DIR)
        list(GET LLVM_CONFIG_OUTPUT 6 ENABLE_ASSERTIONS)

        # Normalize LLVM_CMAKE_DIR. --cmakedir might contain backslashes.
        # CMake assumes slashes as PATH.
        file(TO_CMAKE_PATH ${LLVM_CONFIG_CMAKE_DIR} LLVM_CMAKE_DIR)
    endif()


    if(NOT MSVC_IDE)
        set(LLVM_ENABLE_ASSERTIONS ${ENABLE_ASSERTIONS}
            CACHE BOOL "Enable assertions")
        # Assertions should follow llvm-config's.
        mark_as_advanced(LLVM_ENABLE_ASSERTIONS)
    endif()

    find_package(LLVM REQUIRED HINTS "${LLVM_CMAKE_DIR}")
    list(APPEND CMAKE_MODULE_PATH "${LLVM_DIR}")

    # We can't check LLVM_CONFIG here, because find_package(LLVM ...) also sets
    # LLVM_CONFIG.
    if(NOT LLVM_CONFIG_FOUND)
        # Pull values from LLVMConfig.cmake.  We can drop this once the llvm-config
        # path is removed.
        set(MAIN_INCLUDE_DIR "${LLVM_INCLUDE_DIR}")
        set(LLVM_OBJ_DIR "${LLVM_BINARY_DIR}")
        # N.B. this is just a default value, the CACHE PATHs below can be overriden.
        set(MAIN_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../llvm")
        set(TOOLS_BINARY_DIR "${LLVM_TOOLS_BINARY_DIR}")
        set(LIBRARY_DIR "${LLVM_LIBRARY_DIR}")
    endif()

    set(LLVM_MAIN_INCLUDE_DIR "${MAIN_INCLUDE_DIR}" CACHE PATH "Path to llvm/include")
    set(LLVM_BINARY_DIR "${LLVM_OBJ_ROOT}" CACHE PATH "Path to LLVM build tree")
    set(LLVM_MAIN_SRC_DIR "${MAIN_SRC_DIR}" CACHE PATH "Path to LLVM source tree")
    set(LLVM_TOOLS_BINARY_DIR "${TOOLS_BINARY_DIR}" CACHE PATH "Path to llvm/bin")
    set(LLVM_LIBRARY_DIR "${LIBRARY_DIR}" CACHE PATH "Path to llvm/lib")

    find_program(LLVM_TABLEGEN_EXE "llvm-tblgen" ${LLVM_TOOLS_BINARY_DIR}
                 NO_DEFAULT_PATH)

    # They are used as destination of target generators.
    set(LLVM_RUNTIME_OUTPUT_INTDIR ${CMAKE_BINARY_DIR}/${CMAKE_CFG_INTDIR}/bin)
    set(LLVM_LIBRARY_OUTPUT_INTDIR ${CMAKE_BINARY_DIR}/${CMAKE_CFG_INTDIR}/lib${LLVM_LIBDIR_SUFFIX})
    if(WIN32 OR CYGWIN)
        # DLL platform -- put DLLs into bin.
        set(LLVM_SHLIB_OUTPUT_INTDIR ${LLVM_RUNTIME_OUTPUT_INTDIR})
    else()
        set(LLVM_SHLIB_OUTPUT_INTDIR ${LLVM_LIBRARY_OUTPUT_INTDIR})
    endif()

    option(LLVM_INSTALL_TOOLCHAIN_ONLY
           "Only include toolchain files in the 'install' target." OFF)

    option(LLVM_FORCE_USE_OLD_HOST_TOOLCHAIN
           "Set to ON to force using an old, unsupported host toolchain." OFF)
    option(SOLL_ENABLE_BOOTSTRAP "Generate the clang bootstrap target" OFF)
    option(LLVM_ENABLE_LIBXML2 "Use libxml2 if available." ON)

    include(AddLLVM)
    include(TableGen)
    include(HandleLLVMOptions)
    include(VersionFromVCS)
    include(GetErrcMessages)
    include(LLVMDistributionSupport)

    set(PACKAGE_VERSION "${LLVM_PACKAGE_VERSION}")
    set(BUG_REPORT_URL "${LLVM_PACKAGE_BUGREPORT}" CACHE STRING
        "Default URL where bug reports are to be submitted.")

    if(NOT DEFINED LLVM_INCLUDE_TESTS)
        set(LLVM_INCLUDE_TESTS ON)
    endif()

    include_directories("${LLVM_BINARY_DIR}/include" "${LLVM_MAIN_INCLUDE_DIR}")
    link_directories("${LLVM_LIBRARY_DIR}")

    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib${LLVM_LIBDIR_SUFFIX})
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib${LLVM_LIBDIR_SUFFIX})

    set(BACKEND_PACKAGE_STRING "LLVM ${LLVM_PACKAGE_VERSION}")
else()
    set(BACKEND_PACKAGE_STRING "${PACKAGE_STRING}")
endif() # standalone

if(NOT DEFINED LLVM_COMMON_CMAKE_UTILS)
    set(LLVM_COMMON_CMAKE_UTILS ${CMAKE_CURRENT_SOURCE_DIR}/../cmake)
endif()

include_directories(BEFORE
                    ${CMAKE_CURRENT_BINARY_DIR}/include
                    ${CMAKE_CURRENT_SOURCE_DIR}/include)

include_directories("${LLVM_BINARY_DIR}/include" "${LLVM_INCLUDE_DIR}")
link_directories("${LLVM_LIBRARY_DIR}")

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
            -Wall
            -Wextra
            -Wno-unknown-warning-option
            -Wno-init-list-lifetime
            -Wno-unused-parameter
            -Wno-unused-private-field
    )
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(
            -Wno-redundant-move
    )
endif()

option(SOLL_INCLUDE_TESTS
       "Generate build targets for the Soll unit tests."
       ${LLVM_INCLUDE_TESTS})
option(SOLL_COVERAGE
       "Generate coverage report. \
Require SOLL_INCLUDE_TESTS."
       OFF)

option(SOLL_ENABLE_EVM
       "Enable EVM backend for the SOLL."
       TRUE)

if(SOLL_COVERAGE)
    include(CodeCoverage)
    append_coverage_compiler_flags()
endif()

add_subdirectory(lib)
add_subdirectory(tools)
add_subdirectory(utils)

# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
if(EXISTS ${LLVM_MAIN_SRC_DIR}/utils/lit/lit.py)
    # Note: path not really used, except for checking if lit was found
    set(LLVM_LIT ${LLVM_MAIN_SRC_DIR}/utils/lit/lit.py)
else()
    # Seek installed Lit.
    find_program(LLVM_LIT
                 NAMES llvm-lit lit.py lit
                 PATHS "${LLVM_MAIN_SRC_DIR}/utils/lit"
                 DOC "Path to lit.py")
endif()

if(LLVM_LIT)
    # Define the default arguments to use with 'lit', and an option for the user
    # to override.
    set(LIT_ARGS_DEFAULT "-sv")
    if (MSVC OR XCODE)
        set(LIT_ARGS_DEFAULT "${LIT_ARGS_DEFAULT} --no-progress-bar")
    endif()
    set(LLVM_LIT_ARGS "${LIT_ARGS_DEFAULT}" CACHE STRING "Default options for lit")

    get_errc_messages(LLVM_LIT_ERRC_MESSAGES)

    # On Win32 hosts, provide an option to specify the path to the GnuWin32 tools.
    if( WIN32 AND NOT CYGWIN )
        set(LLVM_LIT_TOOLS_DIR "" CACHE PATH "Path to GnuWin32 tools")
    endif()
else()
    set(LLVM_INCLUDE_TESTS OFF)
endif()

if(SOLL_INCLUDE_TESTS)
    include(CTest)
    include(Catch)

    add_subdirectory(unittests)
    add_subdirectory(test)
    if(SOLL_RUNTIME_TESTS)
        include(FetchContent)

        fetchcontent_declare(
                ssvm-evmc
                GIT_REPOSITORY https://github.com/second-state/ssvm-evmc.git
                GIT_TAG evmc6-0.1.1
        )

        fetchcontent_getproperties(ssvm-evmc)
        if(NOT ssvm-evmc_POPULATED)
            fetchcontent_populate(ssvm-evmc)
        endif()

        add_subdirectory(${ssvm-evmc_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/utils/ssvm-evmc)
        set(SSVM_EVMC_SRC_DIR ${ssvm-evmc_SOURCE_DIR})
    endif()
endif()
