find_package(MbedTLS REQUIRED)

add_library(keycore)

target_sources(keycore
PUBLIC
    keycore.hpp
PRIVATE
    pk.cpp base64.cpp helper.hpp
)

target_include_directories(keycore
PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(keycore PRIVATE MbedTLS::MbedTLS)
