cmake_minimum_required(VERSION 3.9)
project(main-executable C)

if(NOT MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native")
endif()

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/.cmake)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/GLSbot)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/GLSbot)
option(BUILD_SHARED_LIBS "" off)

# include(fetch_libraries)

set(SOURCE_FILES
    source/main.c
)

add_executable(main-executable ${SOURCE_FILES})

target_compile_features(main-executable PUBLIC c_std_99)
set_target_properties(main-executable PROPERTIES OUTPUT_NAME "GLSbot")

target_include_directories(main-executable PUBLIC "extern")
target_include_directories(main-executable PUBLIC "source") # to allow paths relative to project root

target_link_libraries(main-executable PRIVATE m)
