#include <mbedtls/base64.h>
#include <string_view>

#include "base64.hpp"

#include "error.hpp"

namespace licenseman {

namespace base64 {

buffer encode(const buffer &content) {
    size_t olen = 0;
    mbedtls_base64_encode(nullptr, 0, &olen, content.data(), content.size());
    buffer out(olen, 0);
    mbedtls_base64_encode(out.data(), out.size(), &olen, content.data(), content.size());
    return out;
}

buffer decode(const buffer &content) {
    size_t olen = 0;
    int    err = mbedtls_base64_decode(nullptr, 0, &olen, content.data(), content.size());
    if (err == MBEDTLS_ERR_BASE64_INVALID_CHARACTER) {
        handle_mbedtls_error(err);
    }
    buffer out(olen, 0);
    mbedtls_base64_decode(out.data(), out.size(), &olen, content.data(), content.size());
    return out;
}

} // namespace base64

} // namespace licenseman