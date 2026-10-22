#pragma once

#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include "secure_memory.hpp"

namespace keycore {

using buffer = std::vector<uint8_t>;
namespace fs = std::filesystem;

namespace pk {

enum class key_type { NONE, RSA, ECKEY };

class password_required : public std::runtime_error {
  public:
    password_required() : std::runtime_error("The private key requires a passphrase") {}
};

buffer sign(const buffer &content, const fs::path &key_file, std::string_view password = {});
buffer sign(const buffer &content, const std::string_view &key, std::string_view password = {});

bool verify(const buffer &content, const buffer &signature, const fs::path &key_file);
bool verify(const buffer &content, const buffer &signature, const std::string_view &key);

std::tuple<secure_buffer, std::string> gen_key_pair(key_type type = key_type::ECKEY, std::string_view password = {});
secure_buffer encrypt_private_key(std::string_view key, std::string_view password);

} // namespace pk

namespace base64 {

buffer encode(const buffer &content);

buffer decode(const buffer &content);

} // namespace base64

} // namespace keycore
