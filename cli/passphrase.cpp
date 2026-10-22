#include "passphrase.hpp"
#include "secure_io.hpp"

#include <cerrno>
#include <stdexcept>
#include <string>

#ifdef _WIN32
#define NOMINMAX
#include <io.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#endif

namespace {
constexpr std::size_t max_password = 1024;

template <typename Read> keycore::secure_buffer read_line(Read read, bool terminal) {
    keycore::secure_buffer password(max_password + 1);
    std::size_t length = 0;
    for (;;) {
        const auto count = read(password.data() + length);
        if (count < 0) {
            if (errno == EINTR)
                continue;
            throw std::runtime_error("Cannot read passphrase");
        }
        if (!count || password.data()[length] == '\n' || (terminal && password.data()[length] == '\r'))
            break;
        const auto value = password.data()[length];
        if (!value || (terminal && (value == 3 || value == 4 || value == 26))) {
            throw std::runtime_error("Passphrase input cancelled or contains a NUL byte");
        }
        if (terminal && (value == 127 || value == 8)) {
            password.data()[length] = 0;
            if (length)
                password.data()[--length] = 0;
            continue;
        }
        if (length == max_password)
            throw std::runtime_error("Passphrase exceeds 1024 bytes");
        ++length;
    }
    if (!terminal && length && password.data()[length - 1] == '\r')
        --length;
    password.resize(length);
    if (password.empty())
        throw std::runtime_error("An empty passphrase is not allowed");
    return password;
}

keycore::secure_buffer read_terminal(const char *prompt) {
#ifndef _WIN32
    struct terminal_guard {
        int descriptor = -1;
        termios original{};
        bool changed = false;
        ~terminal_guard() {
            if (changed) {
                tcsetattr(descriptor, TCSAFLUSH, &original);
                const auto ignored = write(descriptor, "\n", 1);
                (void)ignored;
            }
            if (descriptor >= 0)
                close(descriptor);
        }
    } terminal;
    terminal.descriptor = open("/dev/tty", O_RDWR | O_CLOEXEC);
    if (terminal.descriptor < 0 || tcgetattr(terminal.descriptor, &terminal.original) != 0) {
        throw std::runtime_error("No terminal available; provide --passphrase-file or --passphrase-fd");
    }
    auto hidden = terminal.original;
    hidden.c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG);
    hidden.c_cc[VMIN] = 1;
    hidden.c_cc[VTIME] = 0;
    if (tcsetattr(terminal.descriptor, TCSAFLUSH, &hidden) != 0) {
        throw std::runtime_error("Cannot disable passphrase echo");
    }
    terminal.changed = true;
    const std::string_view message(prompt);
    if (write(terminal.descriptor, message.data(), message.size()) != static_cast<ssize_t>(message.size())) {
        throw std::runtime_error("Cannot write passphrase prompt");
    }
    return read_line([&](unsigned char *out) { return read(terminal.descriptor, out, 1); }, true);
#else
    struct terminal_guard {
        HANDLE input = INVALID_HANDLE_VALUE;
        HANDLE output = INVALID_HANDLE_VALUE;
        DWORD original = 0;
        bool changed = false;
        ~terminal_guard() {
            if (changed) {
                SetConsoleMode(input, original);
                DWORD written;
                WriteFile(output, "\r\n", 2, &written, nullptr);
            }
            if (input != INVALID_HANDLE_VALUE)
                CloseHandle(input);
            if (output != INVALID_HANDLE_VALUE)
                CloseHandle(output);
        }
    } terminal;
    terminal.input = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                 OPEN_EXISTING, 0, nullptr);
    terminal.output =
        CreateFileW(L"CONOUT$", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (terminal.input == INVALID_HANDLE_VALUE || terminal.output == INVALID_HANDLE_VALUE ||
        !GetConsoleMode(terminal.input, &terminal.original)) {
        throw std::runtime_error("No terminal available; provide --passphrase-file or --passphrase-fd");
    }
    if (!SetConsoleMode(terminal.input,
                        terminal.original & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT))) {
        throw std::runtime_error("Cannot disable passphrase echo");
    }
    terminal.changed = true;
    DWORD written = 0;
    const std::string_view message(prompt);
    if (!WriteFile(terminal.output, message.data(), static_cast<DWORD>(message.size()), &written, nullptr)) {
        throw std::runtime_error("Cannot write passphrase prompt");
    }
    return read_line(
        [&](unsigned char *out) -> int {
            DWORD count = 0;
            return ReadFile(terminal.input, out, 1, &count, nullptr) ? static_cast<int>(count) : -1;
        },
        true);
#endif
}
} // namespace

keycore::secure_buffer read_passphrase(const std::string &file, int descriptor, bool confirm) {
    if (!file.empty()) {
        auto password = keycore::read_secret_file(file, true);
        const auto newline = password.view().find('\n');
        if (newline != std::string_view::npos)
            password.resize(newline);
        if (!password.empty() && password.view().back() == '\r')
            password.resize(password.size() - 1);
        if (password.empty() || password.size() > max_password ||
            password.view().find('\0') != std::string_view::npos) {
            throw std::runtime_error("Passphrase must contain 1 to 1024 non-NUL bytes");
        }
        return password;
    }
    if (descriptor >= 0) {
        return read_line(
            [&](unsigned char *out) {
#ifdef _WIN32
                return _read(descriptor, out, 1);
#else
                return read(descriptor, out, 1);
#endif
            },
            false);
    }
    auto password = read_terminal("Passphrase: ");
    if (confirm) {
        const auto repeated = read_terminal("Confirm passphrase: ");
        if (password.view() != repeated.view())
            throw std::runtime_error("Passphrases do not match");
    }
    return password;
}
