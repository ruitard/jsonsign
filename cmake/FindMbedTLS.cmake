include(FindPackageHandleStandardArgs)

find_path(MBEDTLS_INCLUDE_DIR mbedtls/version.h)

find_library(MBEDTLS_CRYPTO_LIBRARY mbedcrypto)
find_library(MBEDTLS_X509_LIBRARY mbedx509)
find_library(MBEDTLS_TLS_LIBRARY mbedtls)
set(MBEDTLS_LIBRARIES ${MBEDTLS_CRYPTO_LIBRARY} ${MBEDTLS_X509_LIBRARY} ${MBEDTLS_TLS_LIBRARY})

if(MBEDTLS_INCLUDE_DIR)
    file(
        STRINGS ${MBEDTLS_INCLUDE_DIR}/mbedtls/version.h _MBEDTLS_VERLINE
        REGEX "^#define[ \t]+MBEDTLS_VERSION_STRING[\t ].*"
    )
    string(REGEX REPLACE ".*MBEDTLS_VERSION_STRING[\t ]+\"(.*)\"" "\\1" MBEDTLS_VERSION ${_MBEDTLS_VERLINE})
endif()

find_package_handle_standard_args(
    MbedTLS
    REQUIRED_VARS
        MBEDTLS_INCLUDE_DIR
        MBEDTLS_CRYPTO_LIBRARY
        MBEDTLS_X509_LIBRARY
        MBEDTLS_TLS_LIBRARY
    VERSION_VAR MBEDTLS_VERSION
)

if(MbedTLS_FOUND AND NOT TARGET MbedTLS::mbedcrypto)
    add_library(MbedTLS::mbedcrypto UNKNOWN IMPORTED)
    set_target_properties(MbedTLS::mbedcrypto PROPERTIES
        IMPORTED_LOCATION "${MBEDTLS_CRYPTO_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${MBEDTLS_INCLUDE_DIR}"
    )
endif()