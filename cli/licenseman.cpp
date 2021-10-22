#include <iostream>
#include <fstream>
#include <iomanip>

#include <CLI/App.hpp>
#include <CLI/Config.hpp>
#include <CLI/Formatter.hpp>
#include <nlohmann/json.hpp>

#include "licenseman.hpp"

static std::string license_file;
static std::string pubkey_file;
static std::string prikey_file;

static std::string issue_date;
static std::string expiry_date;
static std::string author;
static std::string version;
static std::string licensee;

static nlohmann::ordered_json root;

static std::time_t date_str2time(const std::string &date) {
    std::tm                   tm{0};
    static std::istringstream iss;
    iss.clear();
    iss.str(date);
    if (!(iss >> std::get_time(&tm, "%Y-%m-%d"))) {
        throw std::invalid_argument("get_time");
    }
    if (!iss.eof()) {
        throw std::invalid_argument("get_time");
    }
    return std::mktime(&tm);
}

static licenseman::buffer license_content_join() {
    licenseman::buffer content;
    content.insert(content.end(), issue_date.begin(), issue_date.end());
    content.insert(content.end(), expiry_date.begin(), expiry_date.end());
    content.insert(content.end(), author.begin(), author.end());
    content.insert(content.end(), version.begin(), version.end());
    content.insert(content.end(), licensee.begin(), licensee.end());
    return content;
}

static void sign_license_key() {
    licenseman::fs::path prikey{prikey_file};

    licenseman::buffer content = license_content_join();

    licenseman::buffer signature = licenseman::base64::encode(licenseman::pk::sign(content, prikey));

    root["issue_date"] = issue_date;
    root["expiry_date"] = expiry_date;
    root["author"] = author;
    root["version"] = version;
    root["licensee"] = licensee;
    root["signature"] = std::string(reinterpret_cast<char *>(signature.data()), signature.size());

    if (license_file.empty()) {
        std::cout << root.dump(4) << std::endl;
    } else {
        // write file
        std::ofstream ofs(license_file);
        if (!ofs.is_open()) {
            throw std::runtime_error("license-key file save error.");
        }
        auto content = root.dump(4);
        ofs.write(content.c_str(), content.length());
    }
}

static bool verify_license_key(const nlohmann::ordered_json &json) {
    licenseman::fs::path pubkey{pubkey_file};
    issue_date = root["issue_date"];
    expiry_date = root["expiry_date"];
    author = root["author"];
    version = root["version"];
    licensee = root["licensee"];

    licenseman::buffer content = license_content_join();
    std::string        signature = root["signature"];

    std::time_t issue_time = date_str2time(issue_date);
    std::time_t expiry_time = date_str2time(expiry_date);
    std::time_t now = std::time(nullptr);
    bool        is_license_valid = issue_time <= now && now <= expiry_time;
    if (!is_license_valid) {
        // license valid period expired.
        return false;
    }

    return licenseman::pk::verify(
        content, licenseman::base64::decode(licenseman::buffer(signature.begin(), signature.end())), pubkey);
}

static inline void require(bool flag, const std::string &message) {
    if (!flag) {
        throw std::runtime_error(message);
    }
}

int main(int argc, const char *argv[]) {
    CLI::App app; // message

    app.require_subcommand(1, 1);

    auto sign_cmd = app.add_subcommand("sign");
    sign_cmd->add_option("--issue-date", issue_date, "issue date")->required();
    sign_cmd->add_option("--expiry-date", expiry_date, "expiry date")->required();
    sign_cmd->add_option("--author", author, "license author")->required();
    sign_cmd->add_option("--version", version, "version infomation")->required();
    sign_cmd->add_option("--licensee", licensee, "the licensee")->required();
    sign_cmd->add_option("--pk", prikey_file, "the private key file")->required();
    sign_cmd->add_option("-o", license_file, "save the license-key as file");

    auto verify_cmd = app.add_subcommand("verify");
    verify_cmd->add_option("--pk", pubkey_file, "the public key file")->required();
    verify_cmd->add_option("-f,--filename", license_file, "the license-key file")->required();

    CLI11_PARSE(app, argc, argv);

    if (app.got_subcommand("sign")) {
        std::time_t issue_time = date_str2time(issue_date);
        std::time_t expiry_time = date_str2time(issue_date);
        require(issue_time != -1 && expiry_time != -1, "parse date error");
        sign_license_key();
    }

    if (app.got_subcommand("verify")) {
        std::ifstream ifs(license_file);
        if (!ifs.is_open()) {
            throw std::runtime_error("license-key file not exists");
        }
        root = nlohmann::json::parse(ifs);

        require(root.contains("issue_date"), "issue_date");
        require(root.contains("expiry_date"), "expiry_date");
        require(root.contains("author"), "author");
        require(root.contains("version"), "version");
        require(root.contains("licensee"), "licensee");
        require(root.contains("signature"), "signature");
        std::cout << std::boolalpha << verify_license_key(root) << std::endl;
    }

    return 0;
}