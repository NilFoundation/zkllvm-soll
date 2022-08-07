# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

configure_lit_site_cfg(
  ${CMAKE_CURRENT_SOURCE_DIR}/lit.site.cfg.py.in
  ${CMAKE_CURRENT_BINARY_DIR}/lit.site.cfg.py
  MAIN_CONFIG
  ${CMAKE_CURRENT_SOURCE_DIR}/lit.cfg.py
  )

get_llvm_lit_path(
  lit_base_dir
  lit_file_name
  ALLOW_EXTERNAL
  )

set(LIT_COMMAND "${PYTHON_EXECUTABLE};${lit_base_dir}/${lit_file_name}")

function(add_lit_test name dir)
  set(multival_args DEPENDS)
  cmake_parse_arguments(PARSE_ARGV 0 "LIT_TEST" "" "" "${multival_args}")

  add_test(${name}
    ${LIT_COMMAND}
    --timeout 10
    --param soll_site_config=${CMAKE_CURRENT_BINARY_DIR}/lit.site.cfg
    ${dir}
  )
  set_property(TEST ${name} APPEND PROPERTY DEPENDS ${LIT_TEST_DEPENDS})
endfunction() # end of add_lit_test()

add_lit_test(check-soll-benchmark
  ${CMAKE_CURRENT_BINARY_DIR}/benchmark
  DEPENDS soll)
add_lit_test(check-soll-solidity
  ${CMAKE_CURRENT_BINARY_DIR}/solidity
  DEPENDS soll)
add_lit_test(check-soll-yul
  ${CMAKE_CURRENT_BINARY_DIR}/yul
  DEPENDS soll)
add_lit_test(check-soll-libyul
  ${CMAKE_CURRENT_BINARY_DIR}/libyul
  DEPENDS soll)

if(SOLL_COVERAGE)
  setup_target_for_coverage_gcovr_html(
    NAME coverage
    EXECUTABLE ctest -j ${PROCESSOR_COUNT}
    DEPENDENCIES soll unittests
    BASE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    EXCLUDE
      "${PROJECT_SOURCE_DIR}/utils/json/*"
      "${PROJECT_SOURCE_DIR}/utils/unittests/*"
    )
  setup_target_for_coverage_gcovr_xml(
    NAME codecov
    EXECUTABLE ctest -j ${PROCESSOR_COUNT}
    DEPENDENCIES soll unittests
    BASE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    EXCLUDE
      "${PROJECT_SOURCE_DIR}/utils/json/*"
      "${PROJECT_SOURCE_DIR}/utils/unittests/*"
    )

endif()
