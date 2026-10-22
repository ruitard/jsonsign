#pragma once

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#else
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifdef __linux__
#include <cstdlib>
#include <poll.h>
#include <sys/ioctl.h>
#include <termios.h>
#endif

namespace test {
namespace fs = std::filesystem;
using arguments = std::vector<std::string>;
using namespace std::chrono_literals;

inline void require(bool condition, const std::string &message) {
    if (!condition)
        throw std::runtime_error(message);
}

inline std::string utf8(const fs::path &path) {
    const auto value = path.u8string();
    return {value.begin(), value.end()};
}

inline std::string read_file(const fs::path &path) {
    std::ifstream input(path, std::ios::binary);
    require(input.is_open(), "Cannot open " + utf8(path));
    return {std::istreambuf_iterator<char>(input), {}};
}

inline void write_file(const fs::path &path, std::string_view value) {
    std::ofstream output(path, std::ios::binary);
    output.write(value.data(), static_cast<std::streamsize>(value.size()));
    output.close();
    require(!output.fail(), "Cannot write " + utf8(path));
    fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write);
}

struct temporary_directory {
    fs::path path;
    temporary_directory() {
        std::random_device random;
        for (int attempt = 0; attempt < 100; ++attempt) {
            auto candidate = fs::temp_directory_path() / ("jsonsign-security-" + std::to_string(random()));
            if (fs::create_directory(candidate)) {
                path = std::move(candidate);
                fs::permissions(path, fs::perms::owner_all);
                return;
            }
        }
        throw std::runtime_error("Cannot create temporary test directory");
    }
    temporary_directory(const temporary_directory &) = delete;
    temporary_directory &operator=(const temporary_directory &) = delete;
    ~temporary_directory() {
        std::error_code ignored;
        fs::remove_all(path, ignored);
    }
};

struct process_result {
    unsigned long exit_code;
    std::string output;
    std::string error;
};

#ifdef _WIN32
struct handle {
    HANDLE value;
    explicit handle(HANDLE value) : value(value) {
        require(value != INVALID_HANDLE_VALUE, "Cannot open process handle");
    }
    handle(const handle &) = delete;
    handle &operator=(const handle &) = delete;
    ~handle() { CloseHandle(value); }
};

inline std::wstring wide(const std::string &value) {
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.c_str(), -1, nullptr, 0);
    require(length > 0, "Invalid UTF-8 process argument");
    std::wstring result(static_cast<std::size_t>(length), L'\0');
    require(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.c_str(), -1, result.data(), length) == length,
            "Cannot convert process argument");
    result.pop_back();
    return result;
}

inline std::wstring quote_argument(const std::string &value) {
    std::wstring result = L"\"";
    std::size_t backslashes = 0;
    for (const auto character : wide(value)) {
        if (character == L'\\') {
            ++backslashes;
        } else {
            result.append(backslashes * (character == L'"' ? 2 : 1), L'\\');
            backslashes = 0;
            if (character == L'"')
                result += L'\\';
            result += character;
        }
    }
    result.append(backslashes * 2, L'\\');
    return result + L'"';
}

inline unsigned long execute(const arguments &args, const fs::path &work, bool no_locked_memory) {
    require(!no_locked_memory, "Locked-memory limits are only tested on Linux");
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    handle input(
        CreateFileW((work / ".stdin").c_str(), GENERIC_READ, FILE_SHARE_READ, &security, OPEN_EXISTING, 0, nullptr));
    handle output(
        CreateFileW((work / ".stdout").c_str(), GENERIC_WRITE, FILE_SHARE_READ, &security, CREATE_ALWAYS, 0, nullptr));
    handle error(
        CreateFileW((work / ".stderr").c_str(), GENERIC_WRITE, FILE_SHARE_READ, &security, CREATE_ALWAYS, 0, nullptr));
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = input.value;
    startup.hStdOutput = output.value;
    startup.hStdError = error.value;
    std::wstring command;
    for (const auto &argument : args)
        command += quote_argument(argument) + L' ';
    PROCESS_INFORMATION process{};
    require(CreateProcessW(wide(args.front()).c_str(), command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                           nullptr, work.c_str(), &startup, &process),
            "Cannot start test process");
    handle process_handle(process.hProcess);
    handle thread_handle(process.hThread);
    const auto status = WaitForSingleObject(process.hProcess, 60000);
    if (status != WAIT_OBJECT_0) {
        TerminateProcess(process.hProcess, 1);
        WaitForSingleObject(process.hProcess, INFINITE);
        throw std::runtime_error("Test process timed out or could not be waited for");
    }
    DWORD exit_code;
    require(GetExitCodeProcess(process.hProcess, &exit_code), "Cannot read process exit status");
    return exit_code;
}
#else
struct descriptor {
    int value;
    explicit descriptor(int value) : value(value) { require(value >= 0, "Cannot open process descriptor"); }
    descriptor(const descriptor &) = delete;
    descriptor &operator=(const descriptor &) = delete;
    ~descriptor() { close(value); }
};

struct child_process {
    pid_t pid;
    explicit child_process(pid_t pid) : pid(pid) { require(pid > 0, "Cannot fork test process"); }
    child_process(const child_process &) = delete;
    child_process &operator=(const child_process &) = delete;
    ~child_process() {
        if (pid > 0) {
            kill(-pid, SIGKILL);
            kill(pid, SIGKILL);
            while (waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {
            }
        }
    }
    unsigned long wait() {
        const auto deadline = std::chrono::steady_clock::now() + 60s;
        int status;
        while (std::chrono::steady_clock::now() < deadline) {
            const auto result = waitpid(pid, &status, WNOHANG);
            if (result == pid) {
                pid = 0;
                require(WIFEXITED(status), "Test process terminated by a signal");
                const auto code = WEXITSTATUS(status);
                require(code != 127, "Cannot execute test process");
                return static_cast<unsigned long>(code);
            }
            require(result >= 0 || errno == EINTR, "Cannot wait for test process");
            std::this_thread::sleep_for(10ms);
        }
        throw std::runtime_error("Test process timed out");
    }
};

inline std::vector<char *> native_arguments(const arguments &args) {
    std::vector<char *> values;
    for (const auto &argument : args)
        values.push_back(const_cast<char *>(argument.c_str()));
    values.push_back(nullptr);
    return values;
}

inline unsigned long execute(const arguments &args, const fs::path &work, bool no_locked_memory) {
    descriptor input(open((work / ".stdin").c_str(), O_RDONLY | O_CLOEXEC));
    descriptor output(open((work / ".stdout").c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
    descriptor error(open((work / ".stderr").c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
    auto values = native_arguments(args);
    const auto pid = fork();
    if (pid == 0) {
        if (setsid() < 0 || chdir(work.c_str()) != 0 || dup2(input.value, STDIN_FILENO) < 0 ||
            dup2(output.value, STDOUT_FILENO) < 0 || dup2(error.value, STDERR_FILENO) < 0)
            _exit(127);
        if (no_locked_memory) {
            const rlimit limit{0, 0};
            if (setrlimit(RLIMIT_MEMLOCK, &limit) != 0)
                _exit(127);
        }
        execv(values.front(), values.data());
        _exit(127);
    }
    child_process child(pid);
    return child.wait();
}
#endif

inline process_result run(const arguments &args, const fs::path &work, std::string_view input = {}, bool success = true,
                          bool no_locked_memory = false) {
    write_file(work / ".stdin", input);
    process_result result{execute(args, work, no_locked_memory), read_file(work / ".stdout"),
                          read_file(work / ".stderr")};
    require((result.exit_code == 0) == success, "Unexpected exit status " + std::to_string(result.exit_code) +
                                                    " from " + args.front() + (args.size() > 1 ? " " + args[1] : "") +
                                                    "\n" + result.output + result.error);
    require((result.output + result.error).find("correct horse battery staple") == std::string::npos,
            "Passphrase leaked to command output");
    return result;
}

#ifdef __linux__
inline void terminal_case(const fs::path &work, const arguments &args, const arguments &answers, bool success = true) {
    descriptor master(posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC));
    require(grantpt(master.value) == 0 && unlockpt(master.value) == 0, "Cannot prepare test terminal");
    const auto *slave_name = ptsname(master.value);
    require(slave_name != nullptr, "Cannot locate test terminal");
    auto values = native_arguments(args);
    const auto pid = fork();
    if (pid == 0) {
        if (setsid() < 0 || chdir(work.c_str()) != 0)
            _exit(127);
        const int slave = open(slave_name, O_RDWR | O_CLOEXEC);
        if (slave < 0 || ioctl(slave, TIOCSCTTY, 0) != 0 || dup2(slave, STDIN_FILENO) < 0 ||
            dup2(slave, STDOUT_FILENO) < 0 || dup2(slave, STDERR_FILENO) < 0)
            _exit(127);
        execv(values.front(), values.data());
        _exit(127);
    }
    child_process child(pid);
    std::string output;
    std::size_t next_answer = 0;
    const std::string_view prompts[] = {"Passphrase: ", "Confirm passphrase: "};
    const auto deadline = std::chrono::steady_clock::now() + 45s;
    bool ended = false;
    while (std::chrono::steady_clock::now() < deadline) {
        pollfd event{master.value, POLLIN, 0};
        const auto ready = poll(&event, 1, 100);
        if (ready < 0 && errno == EINTR)
            continue;
        require(ready >= 0, "Cannot poll test terminal");
        if (!ready)
            continue;
        char buffer[4096];
        const auto length = read(master.value, buffer, sizeof(buffer));
        if (length == 0 || (length < 0 && errno == EIO)) {
            ended = true;
            break;
        }
        if (length < 0 && errno == EINTR)
            continue;
        require(length > 0, "Cannot read test terminal");
        output.append(buffer, static_cast<std::size_t>(length));
        if (next_answer < answers.size() && next_answer < 2 && output.find(prompts[next_answer]) != std::string::npos) {
            std::string_view answer(answers[next_answer++]);
            while (!answer.empty()) {
                const auto written = write(master.value, answer.data(), answer.size());
                if (written < 0 && errno == EINTR)
                    continue;
                require(written > 0, "Cannot answer test terminal");
                answer.remove_prefix(static_cast<std::size_t>(written));
            }
        }
    }
    require(ended, "Terminal test timed out");
    require((child.wait() == 0) == success, "Unexpected terminal process status\n" + output);
    require(output.find("correct horse battery staple") == std::string::npos, "Terminal echoed the passphrase");
    termios attributes{};
    require(tcgetattr(master.value, &attributes) == 0 && (attributes.c_lflag & ECHO), "Terminal echo was not restored");
}
#endif
} // namespace test
