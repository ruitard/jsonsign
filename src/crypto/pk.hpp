#pragma once

#include <tuple>
#include "define.hpp"

namespace keycore {

namespace pk {

enum class key_type { RSA, ECKEY };

buffer sign(const buffer &content, const fs::path &keyfile);

bool verify(const buffer &content, const buffer &signature, const fs::path &public_keyfile);

std::tuple<std::string, std::string> gen_key_pair(key_type type = key_type::ECKEY);

} // namespace pk

} // namespace keycore