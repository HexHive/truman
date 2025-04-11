cmake_minimum_required(VERSION 3.21)

# Project name
project(Analyzer)

# Include directories
include_directories(
    include/
    ../Utils/include
    ../Customizations/include
    ../LinuxKernelCustomizations/include
    ../RangeAnalysis/include
    ../z3/include
    ${CMAKE_CURRENT_BINARY_DIR}  # Add binary directory to include generated files
    ${PROTOBUF_DIR}/include
)

# Fetch yaml-cpp
include(FetchContent)
FetchContent_Declare(
    yaml-cpp
    GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
)
FetchContent_MakeAvailable(yaml-cpp)

# Find Protobuf package
find_package(Protobuf 3.20 REQUIRED PATHS ${PROTOBUF_DIR})

# Generate protobuf files
set(PROTO_FILE ${CMAKE_CURRENT_SOURCE_DIR}/device.proto)
protobuf_generate(
    LANGUAGE cpp
    PROTOS ${PROTO_FILE}
    OUT_VAR PROTO_SRCS
)

# Include the directory containing generated protobuf files
include_directories(${CMAKE_CURRENT_BINARY_DIR})

# Source files
file(GLOB SAA_SRCS
    "src/*.cpp"
    "src/bug_detectors/*.cpp"
    "src/bug_detectors/warnings/*.cpp"
    "include/*.h"
    "include/bug_detectors/*.h"
    "include/bug_detectors/warnings/*.h"
)

# Message for debugging
message(STATUS "Source files: ${SAA_SRCS}")

# Add libraries
add_library(Analyzer MODULE ${SAA_SRCS} ${PROTO_SRCS})
add_library(AnalyzerStatic STATIC ${SAA_SRCS} ${PROTO_SRCS})

# Link libraries
target_link_libraries(Analyzer 
    ${SVF_LIB} 
    spdlog::spdlog 
    yaml-cpp::yaml-cpp 
    ${Z3_LIB} 
    Utils 
    Customizations 
    LinuxKernelCustomizations 
    RangeAnalysis 
	protobuf::libprotobuf
)

target_link_libraries(AnalyzerStatic 
    ${SVF_LIB} 
    spdlog::spdlog 
    yaml-cpp::yaml-cpp 
    ${Z3_LIB} 
    Utils 
    Customizations 
    LinuxKernelCustomizations 
    RangeAnalysis 
	protobuf::libprotobuf
)

# Use C++11 to compile our pass (i.e., supply -std=c++11).
target_compile_features(Analyzer PRIVATE cxx_range_for cxx_auto_type)
target_compile_features(AnalyzerStatic PRIVATE cxx_range_for cxx_auto_type)

# Set target properties
set_target_properties(AnalyzerStatic PROPERTIES POSITION_INDEPENDENT_CODE ON)
set_target_properties(Analyzer PROPERTIES COMPILE_FLAGS "-g -fno-rtti")
set_target_properties(AnalyzerStatic PROPERTIES COMPILE_FLAGS "-g -fno-rtti")
