find_package(MbedTLS CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

add_executable(pk_test pk_test.cpp)
target_link_libraries(pk_test PRIVATE keycore)

foreach(key_type IN ITEMS ec rsa)
    file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/pk-${key_type})
    add_test(NAME pk-${key_type} COMMAND pk_test ${key_type})
    set_tests_properties(pk-${key_type} PROPERTIES
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/pk-${key_type}
    )
endforeach()

add_executable(secure_memory_test secure_memory_test.cpp)
target_link_libraries(secure_memory_test PRIVATE keycore MbedTLS::mbedcrypto)
add_test(NAME secure-memory COMMAND secure_memory_test)

add_executable(cli_test cli_test.cpp process.hpp)
target_link_libraries(cli_test PRIVATE keycore nlohmann_json::nlohmann_json)
add_dependencies(cli_test jsign)
find_program(JSONSIGN_TEST_OPENSSL_EXECUTABLE NAMES openssl)
set(openssl_test_argument)
if(JSONSIGN_TEST_OPENSSL_EXECUTABLE)
    set(openssl_test_argument "${JSONSIGN_TEST_OPENSSL_EXECUTABLE}")
endif()
add_test(NAME cli-security COMMAND cli_test $<TARGET_FILE:jsign> ${openssl_test_argument})
set_tests_properties(cli-security PROPERTIES TIMEOUT 180)

if(BUILD_WITH_ASAN)
    # Fake stacks bypass our locked thread stack; LSan's tracer conflicts with PR_SET_DUMPABLE=0.
    set_property(TEST pk-ec pk-rsa secure-memory cli-security APPEND PROPERTY ENVIRONMENT
        "ASAN_OPTIONS=detect_leaks=0:detect_stack_use_after_return=0")
endif()
if(BUILD_WITH_UBSAN)
    set_property(TEST pk-ec pk-rsa secure-memory cli-security APPEND PROPERTY ENVIRONMENT
        "UBSAN_OPTIONS=halt_on_error=1")
endif()
