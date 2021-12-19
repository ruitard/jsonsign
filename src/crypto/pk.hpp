#pragma once

#include <tuple>
#include "define.hpp"

namespace keycore {

namespace pk {

buffer sign(const buffer &content, const fs::path &keyfile);

bool verify(const buffer &content, const buffer &signature, const fs::path &public_keyfile);

namespace rsa {
std::tuple<std::string, std::string> gen_key_pair();
}

} // namespace pk

} // namespace keycore