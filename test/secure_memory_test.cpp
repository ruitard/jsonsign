#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <type_traits>

#include "secure_call.hpp"
#include <mbedtls/platform.h>

#ifdef __linux__
#include <sys/prctl.h>
#include <sys/resource.h>
#endif

namespace {
void require(bool value, const char *message) {
    if (!value)
        throw std::runtime_error(message);
}

void check_mapping(const void *pointer) {
#ifdef __linux__
    std::ifstream maps("/proc/self/smaps");
    std::string line;
    bool found = false;
    const auto address = reinterpret_cast<std::uintptr_t>(pointer);
    while (std::getline(maps, line)) {
        std::uintptr_t begin, end;
        char dash;
        std::istringstream header(line);
        if ((header >> std::hex >> begin >> dash >> end) && dash == '-') {
            found = address >= begin && address < end;
        } else if (found && line.starts_with("VmFlags:")) {
            require(line.find(" lo ") != std::string::npos, "Sensitive mapping is not locked");
            require(line.find(" dd ") != std::string::npos || line.ends_with(" dd"), "Sensitive mapping is dumpable");
            return;
        }
    }
    throw std::runtime_error("Sensitive mapping not found in smaps");
#else
    (void)pointer;
#endif
}
} // namespace

int main() {
    try {
        static_assert(!std::is_copy_constructible_v<keycore::secure_buffer>);
        keycore::initialize_secure_memory();
        keycore::secure_buffer secret(128);
        check_mapping(secret.data());
        std::memset(secret.data(), 0xA5, secret.size());
        auto *address = secret.data();
        secret.resize(32);
        for (std::size_t i = 32; i < 128; ++i)
            require(address[i] == 0, "Truncated bytes were not wiped");
        keycore::secure_buffer moved(std::move(secret));
        require(secret.data() == nullptr && secret.empty(), "Moved-from buffer still owns sensitive data");
        moved.clear();
        for (std::size_t i = 0; i < 128; ++i)
            require(address[i] == 0, "Sensitive buffer was not wiped");

        auto *mbed_buffer = static_cast<unsigned char *>(mbedtls_calloc(4, 64));
        require(mbed_buffer != nullptr, "Protected MbedTLS allocation failed");
        require(reinterpret_cast<std::uintptr_t>(mbed_buffer) % alignof(std::max_align_t) == 0,
                "MbedTLS allocation is misaligned");
        check_mapping(mbed_buffer);
        for (int i = 0; i < 256; ++i)
            require(mbed_buffer[i] == 0, "calloc did not initialize memory");
        mbedtls_free(mbed_buffer);
        require(mbedtls_calloc(std::numeric_limits<std::size_t>::max(), 2) == nullptr, "Allocation overflow accepted");
        keycore::detail::secure_call([] {
            unsigned char stack_value = 1;
            check_mapping(&stack_value);
            return stack_value;
        });
        keycore::disable_process_dumps();
#ifdef __linux__
        require(prctl(PR_GET_DUMPABLE) == 0, "Process is dumpable");
        rlimit limit{};
        require(getrlimit(RLIMIT_CORE, &limit) == 0 && limit.rlim_cur == 0, "Core dumps remain enabled");
#endif
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
