cmake_minimum_required(VERSION 3.20.0)
project(jsign VERSION 1.1.0)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

include(CTest)
enable_testing()

include(FindMbedTLS)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_INSTALL_RPATH "$ORIGIN")
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_INSTALL_PREFIX ${PROJECT_BINARY_DIR}/installed)

if(BUILD_WITH_ASAN)
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
endif()

if(BUILD_WITH_UBSAN)
    add_compile_options(-fsanitize=undefined)
    add_link_options(-fsanitize=undefined)
endif()

add_subdirectory(src)
add_subdirectory(cli)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
