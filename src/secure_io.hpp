#pragma once

#include "secure_memory.hpp"
#include <filesystem>

namespace keycore {

secure_buffer read_secret_file(const std::filesystem::path &path, bool private_permissions = false);
// Exclusive creation: never truncate an existing key or follow a symlink.
void write_key_file(const std::filesystem::path &path, std::string_view contents, bool private_file = true);

} // namespace keycore
