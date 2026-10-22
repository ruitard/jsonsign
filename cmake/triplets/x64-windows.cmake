include("${VCPKG_ROOT_DIR}/triplets/x64-windows.cmake")
list(APPEND VCPKG_HASH_ADDITIONAL_FILES "${VCPKG_ROOT_DIR}/triplets/x64-windows.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/mbedtls.cmake")
