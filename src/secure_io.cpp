#include "secure_io.hpp"

#include <cerrno>
#include <stdexcept>
#include <system_error>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>

#include <sddl.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace keycore {
namespace {
constexpr std::size_t max_secret_file = 65536;

#ifndef _WIN32
struct file_handle {
    int value;
    ~file_handle() {
        if (value >= 0)
            close(value);
    }
};

void check_io(bool success, const char *message) {
    if (!success)
        throw std::system_error(errno, std::generic_category(), message);
}
#else
struct file_handle {
    HANDLE value;
    ~file_handle() {
        if (value != INVALID_HANDLE_VALUE)
            CloseHandle(value);
    }
};

void check_io(bool success, const char *message) {
    if (!success)
        throw std::system_error(GetLastError(), std::system_category(), message);
}
#endif
} // namespace

secure_buffer read_secret_file(const std::filesystem::path &path, bool private_permissions) {
#ifndef _WIN32
    file_handle file{open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)};
    check_io(file.value >= 0, "Cannot open secret file");
    struct stat info {};
    check_io(fstat(file.value, &info) == 0, "Cannot stat secret file");
    if (!S_ISREG(info.st_mode) || info.st_size < 0 || static_cast<std::uintmax_t>(info.st_size) > max_secret_file) {
        throw std::runtime_error("Secret input must be a regular file no larger than 64 KiB");
    }
    if (private_permissions && (info.st_uid != geteuid() || (info.st_mode & 0077) != 0)) {
        throw std::runtime_error("Passphrase file must belong to the current user with no group/other access");
    }
    const auto size = static_cast<std::size_t>(info.st_size);
#else
    (void)private_permissions; // Access is controlled by the Windows file's DACL.
    file_handle file{CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                 FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
    check_io(file.value != INVALID_HANDLE_VALUE, "Cannot open secret file");
    BY_HANDLE_FILE_INFORMATION info{};
    check_io(GetFileInformationByHandle(file.value, &info), "Cannot stat secret file");
    if (GetFileType(file.value) != FILE_TYPE_DISK ||
        info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) || info.nFileSizeHigh ||
        info.nFileSizeLow > max_secret_file) {
        throw std::runtime_error("Secret input must be a regular file no larger than 64 KiB");
    }
    const auto size = static_cast<std::size_t>(info.nFileSizeLow);
#endif
    secure_buffer contents(size + 1);
    std::size_t offset = 0;
    while (offset < size) {
#ifndef _WIN32
        const auto count = read(file.value, contents.data() + offset, size - offset);
        if (count < 0 && errno == EINTR)
            continue;
        check_io(count >= 0, "Cannot read secret file");
#else
        DWORD count = 0;
        check_io(ReadFile(file.value, contents.data() + offset, static_cast<DWORD>(size - offset), &count, nullptr),
                 "Cannot read secret file");
#endif
        if (count == 0)
            throw std::runtime_error("Secret file changed while being read");
        offset += static_cast<std::size_t>(count);
    }
    contents.resize(size);
    return contents;
}

void write_key_file(const std::filesystem::path &path, std::string_view contents, bool private_file) {
#ifndef _WIN32
    file_handle file{
        open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, private_file ? 0600 : 0644)};
    check_io(file.value >= 0, "Cannot create key file (existing files are never overwritten)");
#else
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (private_file) {
        check_io(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;FA;;;SY)(A;;FA;;;OW)", SDDL_REVISION_1,
                                                                      &descriptor, nullptr),
                 "Cannot set key permissions");
    }
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), descriptor, FALSE};
    file_handle file{
        CreateFileW(path.c_str(), GENERIC_WRITE, 0, &attributes, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr)};
    if (descriptor)
        LocalFree(descriptor);
    check_io(file.value != INVALID_HANDLE_VALUE, "Cannot create key file (existing files are never overwritten)");
#endif
    std::size_t offset = 0;
    while (offset < contents.size()) {
#ifndef _WIN32
        const auto count = write(file.value, contents.data() + offset, contents.size() - offset);
        if (count < 0 && errno == EINTR)
            continue;
        check_io(count >= 0, "Cannot write key file");
#else
        DWORD count = 0;
        check_io(WriteFile(file.value, contents.data() + offset, static_cast<DWORD>(contents.size() - offset), &count,
                           nullptr),
                 "Cannot write key file");
#endif
        if (count == 0)
            throw std::runtime_error("Cannot finish writing key file");
        offset += static_cast<std::size_t>(count);
    }
#ifndef _WIN32
    check_io(fsync(file.value) == 0, "Cannot flush key file");
#else
    check_io(FlushFileBuffers(file.value), "Cannot flush key file");
#endif
}

} // namespace keycore
