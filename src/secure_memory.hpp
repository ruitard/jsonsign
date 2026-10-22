#pragma once

#include <cstddef>
#include <string_view>

namespace keycore {

// Install the process-wide MbedTLS allocator before creating any MbedTLS objects.
void initialize_secure_memory();

// Noncopyable storage: locked, excluded from supported OS dumps, wiped on release.
class secure_buffer {
  public:
    secure_buffer() = default;
    explicit secure_buffer(std::size_t size);
    explicit secure_buffer(std::string_view value);
    ~secure_buffer();
    secure_buffer(const secure_buffer &) = delete;
    secure_buffer &operator=(const secure_buffer &) = delete;
    secure_buffer(secure_buffer &&other) noexcept;
    secure_buffer &operator=(secure_buffer &&other) noexcept;

    unsigned char *data() noexcept { return data_; }
    const unsigned char *data() const noexcept { return data_; }
    std::size_t size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }
    std::string_view view() const noexcept;
    // Shrink without reallocating, wiping the removed bytes.
    void resize(std::size_t size);
    void clear() noexcept;

  private:
    unsigned char *data_ = nullptr;
    std::size_t size_ = 0;
    std::size_t capacity_ = 0;
};

// CLI hardening is explicit because it changes process-wide debugging policy.
void disable_process_dumps();

} // namespace keycore
