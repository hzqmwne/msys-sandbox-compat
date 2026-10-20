add_executable(token-dacl-probe token-dacl.cpp)
target_link_libraries(token-dacl-probe PRIVATE advapi32)
add_executable(native-probe native-probe.cpp)
add_executable(native-bridge native-bridge.cpp)
target_link_libraries(native-bridge PRIVATE advapi32)
target_link_libraries(native-probe PRIVATE advapi32)
foreach(target token-dacl-probe native-probe native-bridge)
  target_compile_options(${target} PRIVATE /EHsc)
endforeach()

set(msys_test_import "${CMAKE_CURRENT_BINARY_DIR}/msys-runtime-test.lib")
add_custom_command(OUTPUT "${msys_test_import}"
  COMMAND "${CMAKE_AR}" /nologo /machine:x64 "/def:${CMAKE_CURRENT_SOURCE_DIR}/msys-test.def" "/out:${msys_test_import}"
  DEPENDS msys-test.def VERBATIM)
add_library(late-msys-helper SHARED late-module.cpp "${msys_test_import}")
target_link_libraries(late-msys-helper PRIVATE "${msys_test_import}")
target_link_options(late-msys-helper PRIVATE /BASE:0x63002000000 /INCREMENTAL:NO)
add_library(late-msys-module SHARED late-wrapper.cpp)
target_link_libraries(late-msys-module PRIVATE late-msys-helper)
target_link_options(late-msys-module PRIVATE /BASE:0x63000000000 /INCREMENTAL:NO)

add_library(import-name-runtime SHARED import-name-runtime.cpp)
add_executable(import-name-client import-name-client.cpp)
target_link_libraries(import-name-client PRIVATE import-name-runtime)
set_target_properties(import-name-runtime PROPERTIES OUTPUT_NAME msys-2.0)
foreach(target import-name-runtime import-name-client)
  set_target_properties(${target} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/import-name")
  foreach(configuration DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
    set_target_properties(${target} PROPERTIES RUNTIME_OUTPUT_DIRECTORY_${configuration} "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/import-name")
  endforeach()
endforeach()

# Integration tests create native PSEC instances and must run outside a parent
# sandbox that forbids their creation. They share runtime fixtures, so serialize.
find_program(MSYS_COMPAT_POWERSHELL NAMES pwsh)
if(MSYS_COMPAT_POWERSHELL)
  foreach(suite verify scope conpty late-package process-chain)
    add_test(NAME psec.${suite} COMMAND "${MSYS_COMPAT_POWERSHELL}" -NoProfile
      -File "${CMAKE_CURRENT_SOURCE_DIR}/${suite}.ps1"
      -BinaryDirectory "$<TARGET_FILE_DIR:msys-compat>")
    set_tests_properties(psec.${suite} PROPERTIES RUN_SERIAL TRUE TIMEOUT 180)
  endforeach()
endif()
add_executable(identify-test identify-test.cpp ../src/agent/identify.cpp)
target_compile_options(identify-test PRIVATE /EHsc)
add_test(NAME identify COMMAND identify-test)
