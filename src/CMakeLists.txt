add_library(licensecore)

target_include_directories(licensecore
PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_subdirectory(crypto)

target_link_libraries(licensecore PRIVATE mbedcrypto)