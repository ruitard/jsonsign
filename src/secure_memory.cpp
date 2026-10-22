#include "secure_memory.hpp"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <stdexcept>
#include <unordered_set>
#include <utility>

#include <mbedtls/platform.h>
#include <sodium.h>

#ifdef __linux__
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>
#elif defined(_WIN32)
#define NOMINMAX
#include <windows.h>

#include <werapi.h>
#endif

#ifndef MBEDTLS_PLATFORM_MEMORY
#error "MbedTLS must enable MBEDTLS_PLATFORM_MEMORY; use the project's vcpkg triplets"
#endif

namespace keycore {
namespace {

void initialize_sodium() {
    static const int result = sodium_init();
    if (result < 0) {
        throw std::runtime_error("Cannot initialize secure memory");
    }
}

void *allocate_locked(std::size_t size) {
    initialize_sodium();
    constexpr auto alignment = alignof(std::max_align_t);
    if (size > std::numeric_limits<std::size_t>::max() - alignment) {
        throw std::bad_alloc();
    }
    const auto rounded = (size + alignment - 1) / alignment * alignment;
    void *ptr = sodium_malloc(rounded);
    if (!ptr) {
        throw std::bad_alloc();
    }
    if (sodium_mlock(ptr, rounded) != 0) {
        sodium_free(ptr);
        throw std::runtime_error("Cannot lock sensitive memory; check the process locked-memory limit");
    }
#ifdef __linux__
    // ASan can replace mlock() with a successful no-op. Enforce the kernel lock too.
    if (syscall(SYS_mlock, ptr, rounded) != 0) {
        sodium_free(ptr);
        throw std::runtime_error("Cannot lock sensitive memory; check the process locked-memory limit");
    }
    const auto page_size = static_cast<std::size_t>(sysconf(_SC_PAGESIZE));
    const auto address = reinterpret_cast<std::uintptr_t>(ptr);
    auto *page = reinterpret_cast<void *>(address - address % page_size);
    if (madvise(page, rounded + address % page_size, MADV_DONTDUMP) != 0) {
        sodium_free(ptr);
        throw std::runtime_error("Cannot exclude sensitive memory from core dumps");
    }
#elif defined(_WIN32)
    if (rounded > MAXDWORD || FAILED(WerRegisterExcludedMemoryBlock(ptr, static_cast<DWORD>(rounded)))) {
        sodium_free(ptr);
        throw std::runtime_error("Cannot exclude sensitive memory from Windows error reports");
    }
#endif
    std::memset(ptr, 0, rounded);
    return ptr;
}

void release_locked(void *ptr) noexcept {
    if (ptr) {
#ifdef _WIN32
        WerUnregisterExcludedMemoryBlock(ptr);
#endif
        sodium_free(ptr);
    }
}

struct allocations {
    std::mutex mutex;
    std::unordered_set<void *> pointers;
};

// Keep allocator metadata alive for MbedTLS objects owned by other static objects.
allocations &registry() {
    static auto *state = new allocations;
    return *state;
}

void *protected_calloc(std::size_t count, std::size_t size) noexcept {
    if (!count || !size || count > std::numeric_limits<std::size_t>::max() / size) {
        return nullptr;
    }
    void *ptr = nullptr;
    try {
        ptr = allocate_locked(count * size);
        auto &state = registry();
        std::lock_guard lock(state.mutex);
        state.pointers.insert(ptr);
        return ptr;
    } catch (...) {
        release_locked(ptr);
        return nullptr;
    }
}

void protected_free(void *ptr) noexcept {
    if (!ptr) {
        return;
    }
    auto &state = registry();
    bool ours;
    {
        std::lock_guard lock(state.mutex);
        ours = state.pointers.erase(ptr) != 0;
    }
    if (ours) {
        release_locked(ptr);
    } else {
        // Permit objects allocated by MbedTLS's default allocator before initialization.
        std::free(ptr);
    }
}

} // namespace

void initialize_secure_memory() {
    static const bool initialized = [] {
        initialize_sodium();
        (void)registry();
        if (mbedtls_platform_set_calloc_free(protected_calloc, protected_free) != 0) {
            throw std::runtime_error("Cannot install the secure MbedTLS allocator");
        }
        return true;
    }();
    (void)initialized;
}

secure_buffer::secure_buffer(std::size_t size) : size_(size), capacity_(size) {
    if (size) {
        data_ = static_cast<unsigned char *>(allocate_locked(size));
    }
}

secure_buffer::secure_buffer(std::string_view value) {
    if (value.size() == std::numeric_limits<std::size_t>::max()) {
        throw std::length_error("Sensitive input is too large");
    }
    capacity_ = value.size() + 1;
    data_ = static_cast<unsigned char *>(allocate_locked(capacity_));
    if (!value.empty()) {
        std::memcpy(data_, value.data(), value.size());
    }
    size_ = value.size();
}

secure_buffer::~secure_buffer() { release_locked(data_); }

secure_buffer::secure_buffer(secure_buffer &&other) noexcept
    : data_(std::exchange(other.data_, nullptr)), size_(std::exchange(other.size_, 0)),
      capacity_(std::exchange(other.capacity_, 0)) {}

secure_buffer &secure_buffer::operator=(secure_buffer &&other) noexcept {
    if (this != &other) {
        release_locked(data_);
        data_ = std::exchange(other.data_, nullptr);
        size_ = std::exchange(other.size_, 0);
        capacity_ = std::exchange(other.capacity_, 0);
    }
    return *this;
}

std::string_view secure_buffer::view() const noexcept {
    return data_ ? std::string_view(reinterpret_cast<const char *>(data_), size_) : std::string_view{};
}

void secure_buffer::resize(std::size_t size) {
    if (size > size_) {
        throw std::length_error("secure_buffer can only shrink");
    }
    if (data_) {
        sodium_memzero(data_ + size, capacity_ - size);
    }
    size_ = size;
}

void secure_buffer::clear() noexcept {
    if (data_) {
        sodium_memzero(data_, capacity_);
    }
    size_ = 0;
}

void disable_process_dumps() {
#ifdef __linux__
    const rlimit limit{0, 0};
    if (setrlimit(RLIMIT_CORE, &limit) != 0 || prctl(PR_SET_DUMPABLE, 0) != 0) {
        throw std::runtime_error("Cannot disable process dumps");
    }
#elif defined(_WIN32)
    if (FAILED(WerSetFlags(WER_FAULT_REPORTING_NOHEAP))) {
        throw std::runtime_error("Cannot disable heap error reporting");
    }
#else
    throw std::runtime_error("Process dump protection is unsupported on this platform");
#endif
}

} // namespace keycore
