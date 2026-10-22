#pragma once

#include <string>

#include "secure_memory.hpp"

keycore::secure_buffer read_passphrase(const std::string &file, int descriptor, bool confirm = false);
