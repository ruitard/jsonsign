include("${VCPKG_ROOT_DIR}/triplets/x64-linux.cmake")
list(APPEND VCPKG_HASH_ADDITIONAL_FILES "${VCPKG_ROOT_DIR}/triplets/x64-linux.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/mbedtls.cmake")
