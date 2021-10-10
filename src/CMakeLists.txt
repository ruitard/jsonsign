add_library(licenseman)

target_include_directories(licenseman
PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_subdirectory(crypto)

target_link_libraries(licenseman PRIVATE mbedcrypto)