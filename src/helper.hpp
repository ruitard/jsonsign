#pragma once

#include <stdexcept>
#include <string_view>

#include <mbedtls/error.h>

namespace keycore {

inline void handle_mbedtls_error(int error_code, const std::string_view &funcname, int line) {
    if (error_code == 0) {
        return;
    }
    std::string error_msg(100, '\0');
    mbedtls_strerror(error_code, error_msg.data(), error_msg.size());
    error_msg = error_msg.c_str();
    throw std::runtime_error(error_msg.append("  |").append(funcname).append(":").append(std::to_string(line)));
}

#define HANDLE_MBEDTLS_ERROR(error) handle_mbedtls_error(error, static_cast<const char *>(__FUNCTION__), __LINE__)

} // namespace keycore