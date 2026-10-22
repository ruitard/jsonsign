find_package(MbedTLS CONFIG REQUIRED)
find_package(unofficial-sodium CONFIG REQUIRED)
find_package(Threads REQUIRED)

add_library(keycore)

target_sources(keycore
PUBLIC
    keycore.hpp secure_memory.hpp secure_io.hpp
PRIVATE
    pk.cpp base64.cpp secure_memory.cpp secure_io.cpp pkcs8.cpp pkcs8.hpp secure_call.hpp helper.hpp
)

target_include_directories(keycore
PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(keycore PRIVATE MbedTLS::mbedcrypto unofficial-sodium::sodium Threads::Threads)
if(WIN32)
    target_link_libraries(keycore PRIVATE wer advapi32)
endif()
