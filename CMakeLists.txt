cmake_minimum_required(VERSION 3.12)

project(AegisInspect LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(AegisInspect src/core/types.cpp src/core/exposure_catalog.cpp src/packet/packet.cpp src/ioc/ioc.cpp src/rules/rules.cpp src/policy/policy.cpp)

target_include_directories(AegisInspect PUBLIC include)

foreach(t packetscan iocmatch rulecheck policyaudit)

 add_executable(${t} tools/${t}.cpp)

 target_link_libraries(${t} PRIVATE AegisInspect)

endforeach()

include(CTest)

if(BUILD_TESTING)

 add_executable(AegisInspect_tests tests/test_all.cpp)

 target_link_libraries(AegisInspect_tests PRIVATE AegisInspect)

 add_test(NAME AegisInspect_tests COMMAND AegisInspect_tests)

 foreach(module core packet ioc rules policy)
  add_executable(${module}_module_tests tests/${module}/${module}_tests.cpp)
  target_link_libraries(${module}_module_tests PRIVATE AegisInspect)
  add_test(NAME ${module}_module_tests COMMAND ${module}_module_tests)
 endforeach()

endif()

