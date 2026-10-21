#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

#include "keycore.hpp"

namespace {

void require(bool condition, const char *message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void write_key(const keycore::fs::path &path, const std::string &key) {
    std::ofstream out(path);
    out << key;
    out.close();
    require(!out.fail(), "Failed to write test key");
}

} // namespace

int main(int argc, char *argv[]) {
    try {
        require(argc == 2, "Expected ec or rsa");
        const std::string type = argv[1];
        require(type == "ec" || type == "rsa", "Expected ec or rsa");
        const auto key_type = type == "rsa" ? keycore::pk::key_type::RSA : keycore::pk::key_type::ECKEY;
        const auto [private_key, public_key] = keycore::pk::gen_key_pair(key_type);
        const keycore::fs::path private_path{"test.key"};
        const keycore::fs::path public_path{"test.pub"};
        write_key(private_path, private_key);
        write_key(public_path, public_key);

        const keycore::buffer content{'t', 'e', 's', 't'};
        auto tampered = content;
        tampered.front() ^= 1;

        // Exercise both private-key parsing APIs and both public-key loading APIs.
        for (const auto &signature : {keycore::pk::sign(content, std::string_view{private_key}),
                                      keycore::pk::sign(content, private_path)}) {
            require(keycore::pk::verify(content, signature, std::string_view{public_key}),
                    "In-memory public key rejected a valid signature");
            require(keycore::pk::verify(content, signature, public_path),
                    "Public key file rejected a valid signature");
            require(!keycore::pk::verify(tampered, signature, std::string_view{public_key}),
                    "In-memory public key accepted tampered content");
            require(!keycore::pk::verify(tampered, signature, public_path),
                    "Public key file accepted tampered content");
        }
        keycore::fs::remove(private_path);
        keycore::fs::remove(public_path);
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
