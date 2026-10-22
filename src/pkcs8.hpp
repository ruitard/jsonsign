#pragma once

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>

#include "secure_memory.hpp"

namespace keycore::pk {

secure_buffer export_private_key(const mbedtls_pk_context &key, std::string_view password,
                                 mbedtls_ctr_drbg_context &rng);

} // namespace keycore::pk
