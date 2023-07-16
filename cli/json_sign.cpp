#include <iostream>
#include <fstream>
#include <iomanip>

#include <CLI/App.hpp>
#include <CLI/Config.hpp>
#include <CLI/Formatter.hpp>
#include <nlohmann/json.hpp>

#include "keycore.hpp"

namespace fs = std::filesystem;

static constexpr std::string_view json_signature_name{"|signature|"};

namespace {

std::string json_file;
std::string signed_json_file;
std::string pubkey_file;
std::string prikey_file;

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

[[maybe_unused]] std::string file_content(const fs::path &path) {
    auto        file_size = fs::file_size(path);
    std::string content;
    if (std::ifstream ifs(path, std::ios::binary); ifs.is_open()) {
        content.resize(file_size);
        ifs.read(content.data(), static_cast<std::streamsize>(file_size));
    }
    return content;
}

void sign_json_file() {
    const fs::path prikey{prikey_file};
    require(fs::is_regular_file(prikey), "the key file not exist");

    parse_json_file(json_file);
    require(!root.contains(json_signature_name), "the json file already has a signature");

    const keycore::buffer content = json_content_join(root);

    const keycore::buffer signature = keycore::base64::encode(keycore::pk::sign(content, prikey));
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

int main(int argc, const char *argv[]) {
    CLI::App app{"A tool for Json File Signing, Verification."};

    app.require_subcommand(1, 1);

    std::string type_string = "ec";
    auto       *generate_cmd = app.add_subcommand("generate-key-pair", "Generates a key-pair for signing.");
    generate_cmd->add_option("--type,-t", type_string, "Specify the key type (rsa or ec)");

    auto *sign_cmd = app.add_subcommand("sign", "Sign the supplied json file.");
    sign_cmd->add_option("--key", prikey_file, "Path to the private key file")->required();
    sign_cmd->add_option("-o", signed_json_file, "Specify the signed-json file name");
    sign_cmd->add_option("--file", json_file, "The input json file")->required();

    auto *verify_cmd = app.add_subcommand("verify", "Verify signature and annotations on a json.");
    verify_cmd->add_option("--key", pubkey_file, "Path to the public key file")->required();
    verify_cmd->add_option("--file", signed_json_file, "Path to the signed-json file")->required();

    CLI11_PARSE(app, argc, argv);

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
        keycore::pk::key_type keytype = keycore::pk::key_type::NONE;
        if (type_string == "rsa") {
            keytype = keycore::pk::key_type::RSA;
        } else if (type_string == "ec") {
            keytype = keycore::pk::key_type::ECKEY;
        }
        const auto &[key, public_key] = keycore::pk::gen_key_pair(keytype);
        if (std::ofstream ofs{"jsign.key"}; ofs.is_open()) {
            ofs.write(key.c_str(), static_cast<std::streamsize>(key.length()));
            std::cout << "Private key written to jsign.key" << std::endl;
        }
        if (std::ofstream ofs{"jsign.pub"}; ofs.is_open()) {
            ofs.write(public_key.c_str(), static_cast<std::streamsize>(public_key.length()));
            std::cout << "Public key written to jsign.pub" << std::endl;
        }
    }

    return 0;
}