add_test(
    NAME generate
    COMMAND jsign generate-key-pair
)

add_test(
    NAME sign
    COMMAND jsign sign --file ${CMAKE_CURRENT_SOURCE_DIR}/license.json --key jsign.key -o signed.json
)
set_tests_properties(sign PROPERTIES DEPENDS generate)

add_test(
    NAME verify
    COMMAND jsign verify --file signed.json --key jsign.pub
)
set_tests_properties(verify PROPERTIES DEPENDS sign)

add_executable(pk_test pk_test.cpp)
target_link_libraries(pk_test PRIVATE keycore)

foreach(key_type IN ITEMS ec rsa)
    file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/pk-${key_type})
    add_test(NAME pk-${key_type} COMMAND pk_test ${key_type})
    set_tests_properties(pk-${key_type} PROPERTIES
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/pk-${key_type}
    )
endforeach()
