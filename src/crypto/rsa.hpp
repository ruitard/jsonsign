#pragma once

#include <string>

#include "define.hpp"

namespace licenseman {

namespace RSA {

buffer sign(const buffer &content, const buffer &private_key, const buffer &password = buffer());
buffer sign(const buffer &content, const fs::path &private_keyfile, const std::string &password = std::string());

bool verify(const buffer &content, const buffer &signature, const buffer &public_key);
bool verify(const buffer &content, const buffer &signature, const fs::path &public_keyfile);

} // namespace RSA

} // namespace licenseman