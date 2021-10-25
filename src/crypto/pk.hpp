#pragma once

#include "define.hpp"

namespace licenseman {

namespace pk {

buffer sign(const buffer &content, const buffer &private_key, const buffer &password = buffer());
buffer sign(const buffer &content, const fs::path &private_keyfile, const std::string &password = std::string());

bool verify(const buffer &content, const buffer &signature, const buffer &public_key);
bool verify(const buffer &content, const buffer &signature, const fs::path &public_keyfile);

namespace rsa {
void gen_key_pair(std::string &key, std::string &public_key);
}

} // namespace pk

} // namespace licenseman