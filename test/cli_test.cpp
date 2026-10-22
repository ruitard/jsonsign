#include "keycore.hpp"
#include "process.hpp"

#include <nlohmann/json.hpp>

namespace {
namespace fs = std::filesystem;
using nlohmann::json;
using test::arguments;
using test::read_file;
using test::require;
using test::run;
using test::utf8;
using test::write_file;

const std::string password = "correct horse battery staple\n";

std::string encode_base64(std::string_view value) {
    const auto result = keycore::base64::encode({value.begin(), value.end()});
    return {result.begin(), result.end()};
}

std::string decode_base64(const std::string &value) {
    const auto result = keycore::base64::decode({value.begin(), value.end()});
    return {result.begin(), result.end()};
}

struct cli_runner {
    std::string executable;
    fs::path work;
    test::process_result operator()(arguments args, std::string_view input = {}, bool success = true,
                                    bool no_locked_memory = false) const {
        args.insert(args.begin(), executable);
        return run(args, work, input, success, no_locked_memory);
    }
};

void check_algorithm(const fs::path &root, const std::string &executable, const std::string &openssl,
                     const std::string &algorithm) {
    const auto work = root / algorithm;
    fs::create_directory(work);
    const cli_runner cli{executable, work};
    const auto external = [&](arguments args) {
        args.insert(args.begin(), openssl);
        return run(args, work);
    };
    write_file(work / "passphrase", password);
    write_file(work / "passphrase-out", password);
    const json source = {{"licensee", "sample"}, {"payload", {{"b", 2}, {"a", 1}}}};
    write_file(work / "input.json", source.dump());

    cli({"generate-key-pair", "--type", algorithm, "--passphrase-fd", "0"}, password);
    const auto encrypted = read_file(work / "jsign.key");
    require(encrypted.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"), "Missing encrypted PEM header");
#ifndef _WIN32
    require((fs::status(work / "jsign.key").permissions() & fs::perms::mask) ==
                (fs::perms::owner_read | fs::perms::owner_write),
            "Private key permissions are not 0600");
#endif
    cli({"sign", "--key", "jsign.key", "--file", "input.json", "-o", "signed.json", "--passphrase-file", "passphrase"});
    cli({"verify", "--key", "jsign.pub", "--file", "signed.json"});
    auto signed_json = json::parse(read_file(work / "signed.json"));
    nlohmann::ordered_json reordered = nlohmann::ordered_json::object();
    for (auto item = signed_json.rbegin(); item != signed_json.rend(); ++item)
        reordered[item.key()] = item.value();
    write_file(work / "reordered.json", reordered.dump());
    cli({"verify", "--key", "jsign.pub", "--file", "reordered.json"});
    auto tampered = signed_json;
    tampered["licensee"] = "tampered";
    write_file(work / "tampered.json", tampered.dump());
    cli({"verify", "--key", "jsign.pub", "--file", "tampered.json"}, {}, false);
    cli({"sign", "--key", "jsign.key", "--file", "input.json", "-o", "bad.json", "--passphrase-fd", "0"}, "incorrect\n",
        false);
    require(!fs::exists(work / "bad.json"), "Wrong password created an output file");
    cli({"sign", "--key", "jsign.key", "--file", "input.json"}, {}, false);
    cli({"generate-key-pair", "--no-passphrase"}, {}, false);
    require(read_file(work / "jsign.key") == encrypted, "Existing key was overwritten");

    cli({"generate-key-pair", "--type", algorithm, "--no-passphrase", "--private-key", "plain.key", "--public-key",
         "plain.pub"});
    cli({"sign", "--key", "plain.key", "--file", "input.json", "-o", "plain-signed.json"});
    cli({"verify", "--key", "plain.pub", "--file", "plain-signed.json"});
    for (const auto *name : {"protected.key", "protected-again.key"})
        cli({"encrypt-key", "--key", "plain.key", "--output", name, "--passphrase-fd", "0"}, password);
    require(read_file(work / "protected.key") != read_file(work / "protected-again.key"),
            "Encrypted exports reused salt and IV");
    cli({"sign", "--key", "protected.key", "--file", "input.json", "-o", "converted-signed.json", "--passphrase-fd",
         "0"},
        password);
    cli({"verify", "--key", "plain.pub", "--file", "converted-signed.json"});
    cli({"encrypt-key", "--key", "plain.key", "--output", "plain.key", "--passphrase-fd", "0"}, password, false);

    if (!openssl.empty()) {
        external({"pkey", "-in", "jsign.key", "-passin", "file:passphrase", "-check", "-noout"});
        const auto info = external({"asn1parse", "-in", "jsign.key"}).output;
        for (const auto *marker : {"PBES2", "PBKDF2", "hmacWithSHA256", "aes-256-cbc", "0927C0"})
            require(info.find(marker) != std::string::npos, std::string("Missing PKCS#8 parameter: ") + marker);
        write_file(work / "payload.bin", source.dump());
        write_file(work / "signature.bin", decode_base64(signed_json.at("|signature|").get<std::string>()));
        external({"dgst", "-sha256", "-verify", "jsign.pub", "-signature", "signature.bin", "payload.bin"});
        external({"dgst", "-sha256", "-sign", "jsign.key", "-passin", "file:passphrase", "-out", "openssl.sig",
                  "payload.bin"});
        signed_json["|signature|"] = encode_base64(read_file(work / "openssl.sig"));
        write_file(work / "openssl-signed.json", signed_json.dump());
        cli({"verify", "--key", "jsign.pub", "--file", "openssl-signed.json"});

        arguments options = algorithm == "ec" ? arguments{"-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"}
                                              : arguments{"-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"};
        arguments generate{"genpkey"};
        generate.insert(generate.end(), options.begin(), options.end());
        generate.insert(generate.end(), {"-aes-256-cbc", "-pass", "file:passphrase", "-out", "external.key"});
        external(generate);
        external({"pkey", "-in", "external.key", "-passin", "file:passphrase", "-pubout", "-out", "external.pub"});
        cli({"sign", "--key", "external.key", "--file", "input.json", "-o", "external-signed.json", "--passphrase-fd",
             "0"},
            password);
        cli({"verify", "--key", "external.pub", "--file", "external-signed.json"});
        if (algorithm == "ec") {
            external({"pkcs8", "-topk8", "-in", "external.key", "-passin", "file:passphrase", "-passout",
                      "file:passphrase-out", "-v2", "aes-256-cbc", "-outform", "DER", "-out", "external.der"});
            cli({"sign", "--key", "external.der", "--file", "input.json", "--passphrase-fd", "0"}, password);
        }
    }
    std::cout << algorithm << ": encrypted/plain keys, conversion, password failures and tamper rejection passed"
              << (openssl.empty() ? " (OpenSSL checks skipped)\n" : "; OpenSSL interoperability passed\n");
}

void check_failures(const fs::path &root, const std::string &executable) {
    const auto work = root / "failures";
    fs::create_directory(work);
    const cli_runner cli{executable, work};
    for (const auto &input : {std::string("\n"), std::string(1025, 'a') + '\n', std::string("with\0nul\n", 9)}) {
        cli({"generate-key-pair", "--passphrase-fd", "0"}, input, false);
        require(!fs::exists(work / "jsign.key"), "Invalid password created a key");
    }
    cli({"generate-key-pair"}, {}, false);
    cli({"generate-key-pair", "--no-passphrase", "--passphrase-fd", "0"}, {}, false);
    cli({"generate-key-pair", "--no-passphrase", "--private-key", "same", "--public-key", "same"}, {}, false);
#ifdef __linux__
    cli({"generate-key-pair", "--no-passphrase"}, {}, false, true);
    require(!fs::exists(work / "jsign.key"), "Failed memory lock created a key");
    const auto password_file = root / "ec/passphrase";
    fs::permissions(password_file,
                    fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read | fs::perms::others_read);
    cli_runner{executable, root / "ec"}(
        {"sign", "--key", "jsign.key", "--file", "input.json", "--passphrase-file", "passphrase"}, {}, false);
    fs::permissions(password_file, fs::perms::owner_read | fs::perms::owner_write);
    fs::create_symlink(password_file, work / "passphrase-link");
    cli({"generate-key-pair", "--passphrase-file", "passphrase-link"}, {}, false);
    test::terminal_case(work, {executable, "generate-key-pair"}, {password, "different\n"}, false);
    test::terminal_case(work, {executable, "generate-key-pair"}, {std::string(1, '\x03')}, false);
    test::terminal_case(work, {executable, "generate-key-pair"}, {password, password});
    write_file(work / "input.json", R"({"payload":"terminal test"})");
    test::terminal_case(work, {executable, "sign", "--key", "jsign.key", "--file", "input.json", "-o", "signed.json"},
                        {password});
    cli({"verify", "--key", "jsign.pub", "--file", "signed.json"});
    std::cout << "linux: permission checks, lock failure, terminal confirmation, no echo and cancellation passed\n";
#endif
}
} // namespace

int main(int argc, char *argv[]) {
    try {
        require(argc == 2 || argc == 3, "Expected jsign and optional OpenSSL executable paths");
        const auto executable = utf8(fs::absolute(argv[1]));
        const std::string openssl = argc == 3 ? utf8(fs::absolute(argv[2])) : "";
        const test::temporary_directory temporary;
        for (const auto *algorithm : {"ec", "rsa"})
            check_algorithm(temporary.path, executable, openssl, algorithm);
        check_failures(temporary.path, executable);
        return 0;
    } catch (const std::exception &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
