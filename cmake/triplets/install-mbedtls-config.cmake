# Keep the public MbedTLS configuration available to consumers and binary caches.
file(INSTALL "${CMAKE_CURRENT_LIST_DIR}/jsonsign_mbedtls_config.h"
    DESTINATION "${CURRENT_PACKAGES_DIR}/include")
