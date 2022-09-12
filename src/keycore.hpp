#pragma once

#include <vector>
#include <tuple>
#include <filesystem>
#include <string_view>
#include <variant>

namespace keycore {

using buffer = std::vector<uint8_t>;
namespace fs = std::filesystem;

namespace pk {

enum class key_type { NONE, RSA, ECKEY };

buffer sign(const buffer &content, const std::variant<fs::path, std::string_view> &key);

bool verify(const buffer &content, const buffer &signature, const std::variant<fs::path, std::string_view> &key);

std::tuple<std::string, std::string> gen_key_pair(key_type type = key_type::ECKEY);

} // namespace pk

namespace base64 {

buffer encode(const buffer &content);

buffer decode(const buffer &content);

} // namespace base64

} // namespace keycore