#pragma once

#include "define.hpp"

namespace licenseman {

namespace Base64 {

buffer encode(const buffer &content);

buffer decode(const buffer &content);

} // namespace Base64

} // namespace licenseman