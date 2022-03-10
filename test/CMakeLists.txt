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
