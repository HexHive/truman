cmake_minimum_required(VERSION 3.14)

project(truman)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
	message("Setting build type to 'RelWithDebInfo' as none was specified.")
	set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Choose the type of build." FORCE)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -DSPDLOG_ACTIVE_LEVEL=1")
endif()

find_package(LLVM 13 REQUIRED CONFIG PATHS ${LLVM_DIR})
add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS} ${PROJECT_SOURCE_DIR}/include)
include_directories(SYSTEM ${SVF_SOURCE_DIR}/include)
link_directories(${LLVM_LIBRARY_DIRS})
llvm_map_components_to_libnames(llvm_libs core ipo irreader support)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(FetchContent)

FetchContent_Declare(
	spdlog
	GIT_REPOSITORY https://github.com/gabime/spdlog.git
	GIT_TAG	v1.x
)

FetchContent_Declare(
	yaml-cpp
	GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
)

FetchContent_MakeAvailable(spdlog yaml-cpp)

include_directories(z3/include)
link_directories(z3/bin)
add_subdirectory(RangeAnalysis)
add_subdirectory(Customizations)
add_subdirectory(LinuxKernelCustomizations)
add_subdirectory(Utils)
add_subdirectory(Analyzer)
