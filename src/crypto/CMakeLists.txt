find_package(MbedTLS REQUIRED)

target_sources(keycore
PRIVATE
    pk.cpp pk.hpp
    base64.cpp base64.hpp
    error.hpp
)

target_link_libraries(keycore PRIVATE MbedTLS::MbedTLS)