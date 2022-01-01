#include <iostream>
#include <fstream>
#include <iomanip>

#include <CLI/App.hpp>
#include <CLI/Config.hpp>
#include <CLI/Formatter.hpp>
#include <nlohmann/json.hpp>

#include "keycore.hpp"

namespace fs = std::filesystem;

static constexpr const std::string_view json_signature_name{"#@signature@#"};

static std::string json_file;
static std::string signed_json_file;
static std::string pubkey_file;
static std::string prikey_file;

static nlohmann::ordered_json root;

static inline void require(bool flag, const std::string &message) {
    if (!flag) {
        throw std::runtime_error(message);
    }
}

static inline void parse_json_file(const std::string &jsonfile) {
    if (std::ifstream ifs{jsonfile}; ifs.is_open()) {
        root = nlohmann::json::parse(ifs);
    } else {
        throw std::runtime_error("open json file failed");
    }
}

static keycore::buffer json_content_join(const nlohmann::ordered_json &json_root) {
    std::string content = json_root.dump();
    return {content.begin(), content.end()};
}

static void sign_json_file() {
    fs::path prikey{prikey_file};
    require(fs::is_regular_file(prikey), "the key file not exist");

    parse_json_file(json_file);
    require(!root.contains(json_signature_name), "the json file already has a signature");

    keycore::buffer content = json_content_join(root);

    keycore::buffer signature = keycore::base64::encode(keycore::pk::sign(content, prikey));
    root[json_signature_name] = std::string(reinterpret_cast<char *>(signature.data()), signature.size());
    const auto result = root.dump(4);
    if (signed_json_file.empty()) {
        std::cout << result << std::endl;
    } else {
        if (std::ofstream ofs(signed_json_file); ofs.is_open()) {
            ofs.write(result.c_str(), result.length());
        } else {
            throw std::runtime_error("the signed-json file saved error.");
        }
    }
}

static bool verify_json_file() {
    fs::path pubkey{pubkey_file};
    require(fs::is_regular_file(pubkey), "the key file not exist");

    parse_json_file(signed_json_file);
    require(root.contains(json_signature_name), "the json file doesn't have a signature");
    std::string signature = root[json_signature_name];
    root.erase(json_signature_name);
    keycore::buffer content = json_content_join(root);

    return keycore::pk::verify(content, keycore::base64::decode(keycore::buffer(signature.begin(), signature.end())),
                               pubkey);
}

int main(int argc, const char *argv[]) {
    CLI::App app{"A tool for Json File Signing, Verification."};

    app.require_subcommand(1, 1);

    auto generate_cmd = app.add_subcommand("generate-key-pair", "Generates a key-pair for signing.");

    auto sign_cmd = app.add_subcommand("sign", "Sign the supplied json file.");
    sign_cmd->add_option("--key", prikey_file, "Path to the private key file")->required();
    sign_cmd->add_option("-o", signed_json_file, "Specify the signed-json file name");
    sign_cmd->add_option("--file", json_file, "The input json file")->required();

    auto verify_cmd = app.add_subcommand("verify", "Verify signature and annotations on a json.");
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
        }
    }

    if (app.got_subcommand("generate-key-pair")) {
        const auto &[key, public_key] = keycore::pk::ecdsa::gen_key_pair();
        if (std::ofstream ofs{"jsign.key"}; ofs.is_open()) {
            ofs.write(key.c_str(), key.length());
            std::cout << "Private key written to jsign.key" << std::endl;
        }
        if (std::ofstream ofs{"jsign.pub"}; ofs.is_open()) {
            ofs.write(public_key.c_str(), public_key.length());
            std::cout << "Public key written to jsign.pub" << std::endl;
        }
    }

    return 0;
}