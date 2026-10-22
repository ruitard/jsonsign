#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

#include "keycore.hpp"
#include "secure_io.hpp"

namespace {

void require(bool condition, const char *message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
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
        keycore::fs::remove(private_path);
        keycore::fs::remove(public_path);
        keycore::write_key_file(public_path, public_key, false);
        const auto encrypted_key = keycore::pk::encrypt_private_key(private_key.view(), "test passphrase");
        require(encrypted_key.view().starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"),
                "Missing encrypted PEM header");

        const keycore::buffer content{'t', 'e', 's', 't'};
        auto tampered = content;
        tampered.front() ^= 1;

        for (const auto key : {private_key.view(), encrypted_key.view()}) {
            const auto password = key == encrypted_key.view() ? "test passphrase" : "";
            keycore::write_key_file(private_path, key);
            // Both key formats, both private-key parsing APIs, both public-key loading APIs.
            for (const auto &signature :
                 {keycore::pk::sign(content, key, password), keycore::pk::sign(content, private_path, password)}) {
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
        }
        bool missing_password = false;
        try {
            keycore::pk::sign(content, encrypted_key.view());
        } catch (const keycore::pk::password_required &) {
            missing_password = true;
        }
        require(missing_password, "Encrypted key did not require a password");
        bool wrong_password = false;
        try {
            keycore::pk::sign(content, encrypted_key.view(), "wrong password");
        } catch (const std::runtime_error &) {
            wrong_password = true;
        }
        require(wrong_password, "Encrypted key accepted the wrong password");
        keycore::fs::remove(private_path);
        keycore::fs::remove(public_path);
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
