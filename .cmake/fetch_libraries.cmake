include(FetchContent)

# Include zlib-ng
set(ZLIB_ENABLE_TESTS OFF)
set(WITH_NATIVE_INSTRUCTIONS ON)

FetchContent_Declare(
        zlib
        GIT_REPOSITORY https://github.com/zlib-ng/zlib-ng
        GIT_TAG        2.0.6
)

FetchContent_MakeAvailable(zlib)

find_package(json-c CONFIG)
if(NOT json-c_FOUND)
    FetchContent_Declare(
            json-c
            GIT_REPOSITORY https://github.com/json-c/json-c
            GIT_TAG        json-c-0.15
    )
    FetchContent_MakeAvailable(json-c)
endif()