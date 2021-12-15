#pragma once

#include "define.hpp"

namespace licenseman {

namespace pk {

buffer sign(const buffer &content, const fs::path &keyfile);

bool verify(const buffer &content, const buffer &signature, const fs::path &public_keyfile);

namespace rsa {
void gen_key_pair(std::string &key, std::string &public_key);
}

} // namespace pk

} // namespace licenseman