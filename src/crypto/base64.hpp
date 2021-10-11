#pragma once

#include "define.hpp"

namespace licenseman {

namespace base64 {

buffer encode(const buffer &content);

buffer decode(const buffer &content);

} // namespace base64

} // namespace licenseman