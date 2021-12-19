#pragma once

#include <stdexcept>

#include <mbedtls/error.h>

namespace keycore {

inline void handle_mbedtls_error(int error_code) {
    if (error_code == 0) {
        return;
    }
    std::string error_msg(100, '\0');
    mbedtls_strerror(error_code, error_msg.data(), error_msg.size());
    throw std::runtime_error(error_msg);
}

}