add_library(keycore)

target_sources(keycore
PRIVATE
    define.hpp
    keycore.hpp
)

target_include_directories(keycore
PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_subdirectory(crypto)

target_link_libraries(keycore PRIVATE mbedcrypto)