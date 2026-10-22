#include <iostream>
#include <fstream>

#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>

#include "keycore.hpp"
#include "secure_io.hpp"
#include "passphrase.hpp"

namespace fs = std::filesystem;

static constexpr std::string_view json_signature_name{"|signature|"};

namespace {

std::string json_file;
std::string signed_json_file;
std::string pubkey_file;
std::string prikey_file;
std::string passphrase_file;
int passphrase_fd = -1;

nlohmann::ordered_json root;

inline void require(bool flag, const std::string &message) {
    if (!flag) {
        throw std::runtime_error(message);
    }
}

inline void parse_json_file(const std::string &jsonfile) {
    if (std::ifstream ifs{jsonfile}; ifs.is_open()) {
        root = nlohmann::json::parse(ifs);
    } else {
        throw std::runtime_error("open json file failed");
    }
}

keycore::buffer json_content_join(const nlohmann::ordered_json &json_root) {
    std::string content = json_root.dump();
    return {content.begin(), content.end()};
}
void sign_json_file() {
    const fs::path prikey{prikey_file};
    require(fs::is_regular_file(prikey), "the key file not exist");

    parse_json_file(json_file);
    require(!root.contains(json_signature_name), "the json file already has a signature");

    const keycore::buffer content = json_content_join(root);

    keycore::secure_buffer password;
    if (!passphrase_file.empty() || passphrase_fd >= 0) {
        password = read_passphrase(passphrase_file, passphrase_fd);
    }
    keycore::buffer raw_signature;
    try {
        raw_signature = keycore::pk::sign(content, prikey, password.view());
    } catch (const keycore::pk::password_required &) {
        if (!password.empty()) throw;
        password = read_passphrase({}, -1);
        raw_signature = keycore::pk::sign(content, prikey, password.view());
    }
    password.clear();
    const keycore::buffer signature = keycore::base64::encode(raw_signature);
    root[json_signature_name] = std::string_view(reinterpret_cast<const char *>(signature.data()), signature.size());
    const auto result = root.dump(4);
    if (signed_json_file.empty()) {
        std::cout << result << std::endl;
    } else {
        if (std::ofstream ofs(signed_json_file); ofs.is_open()) {
            ofs.write(result.c_str(), static_cast<std::streamsize>(result.length()));
        } else {
            throw std::runtime_error("the signed-json file saved error.");
        }
    }
}

bool verify_json_file() {
    const fs::path pubkey{pubkey_file};
    require(fs::is_regular_file(pubkey), "the key file not exist");

    parse_json_file(signed_json_file);
    require(root.contains(json_signature_name), "the json file doesn't have a signature");
    const std::string signature = root[json_signature_name];
    root.erase(json_signature_name);
    const keycore::buffer content = json_content_join(root);

    return keycore::pk::verify(content, keycore::base64::decode(keycore::buffer(signature.begin(), signature.end())),
                               pubkey);
}

} // namespace

int run(int argc, const char *argv[]) {
    CLI::App app{"A tool for Json File Signing, Verification."};

    app.require_subcommand(1, 1);

    std::string type_string = "ec";
    auto       *generate_cmd = app.add_subcommand("generate-key-pair", "Generates a key-pair for signing.");
    generate_cmd->add_option("--type,-t", type_string, "Specify the key type (rsa or ec)")
        ->check(CLI::IsMember({"rsa", "ec"}));
    bool no_passphrase = false;
    std::string private_output = "jsign.key";
    std::string public_output = "jsign.pub";
    generate_cmd->add_flag("--no-passphrase", no_passphrase, "Explicitly generate an unencrypted private key");
    generate_cmd->add_option("--private-key", private_output, "Private key output path");
    generate_cmd->add_option("--public-key", public_output, "Public key output path");

    std::string encrypted_output;
    auto *encrypt_cmd = app.add_subcommand("encrypt-key", "Encrypt an existing unencrypted private key.");
    encrypt_cmd->add_option("--key", prikey_file, "Input private key")->required();
    encrypt_cmd->add_option("--output,-o", encrypted_output, "Encrypted private key output path")->required();

    auto *sign_cmd = app.add_subcommand("sign", "Sign the supplied json file.");
    sign_cmd->add_option("--key", prikey_file, "Path to the private key file")->required();
    sign_cmd->add_option("-o", signed_json_file, "Specify the signed-json file name");
    sign_cmd->add_option("--file", json_file, "The input json file")->required();

    auto *verify_cmd = app.add_subcommand("verify", "Verify signature and annotations on a json.");
    verify_cmd->add_option("--key", pubkey_file, "Path to the public key file")->required();
    verify_cmd->add_option("--file", signed_json_file, "Path to the signed-json file")->required();

    for (auto *command : {generate_cmd, sign_cmd, encrypt_cmd}) {
        auto *file_option = command->add_option("--passphrase-file", passphrase_file,
            "Read the passphrase from the first line of a protected file");
        auto *fd_option = command->add_option("--passphrase-fd", passphrase_fd,
            "Read the passphrase from a file descriptor")->check(CLI::NonNegativeNumber);
        file_option->excludes(fd_option);
        if (command == generate_cmd) {
            file_option->excludes("--no-passphrase");
            fd_option->excludes("--no-passphrase");
        }
    }

    CLI11_PARSE(app, argc, argv);

    if (!app.got_subcommand("verify")) keycore::disable_process_dumps();

    if (app.got_subcommand("sign")) {
        sign_json_file();
    }

    if (app.got_subcommand("verify")) {
        if (verify_json_file()) {
            std::cout << "The signature were verified against the specified public key" << std::endl;
        } else {
            std::cout << "Verify signature failed" << std::endl;
            return EXIT_FAILURE;
        }
    }

    if (app.got_subcommand("generate-key-pair")) {
        require(!fs::exists(private_output) && !fs::exists(public_output), "Key output files already exist");
        require(fs::absolute(private_output).lexically_normal() != fs::absolute(public_output).lexically_normal(),
                "Private and public key output paths must differ");
        keycore::secure_buffer password;
        if (!no_passphrase) password = read_passphrase(passphrase_file, passphrase_fd, true);
        const auto keytype = type_string == "rsa" ? keycore::pk::key_type::RSA : keycore::pk::key_type::ECKEY;
        auto [key, public_key] = keycore::pk::gen_key_pair(keytype, password.view());
        password.clear();
        keycore::write_key_file(private_output, key.view());
        key.clear();
        keycore::write_key_file(public_output, public_key, false);
        std::cout << "Private key written to " << private_output << '\n';
        std::cout << "Public key written to " << public_output << '\n';
    }

    if (app.got_subcommand("encrypt-key")) {
        require(!fs::exists(encrypted_output), "Key output file already exists");
        auto password = read_passphrase(passphrase_file, passphrase_fd, true);
        auto input = keycore::read_secret_file(prikey_file);
        auto encrypted = keycore::pk::encrypt_private_key(input.view(), password.view());
        input.clear();
        password.clear();
        keycore::write_key_file(encrypted_output, encrypted.view());
        std::cout << "Encrypted private key written to " << encrypted_output << '\n';
    }

    return 0;
}

int main(int argc, const char *argv[]) {
    try {
        return run(argc, argv);
    } catch (const std::exception &error) {
        std::cerr << "Error: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
