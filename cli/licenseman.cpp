#include <iostream>

#include "licenseman.hpp"
#include "CLI/App.hpp"
#include "CLI/Config.hpp"
#include "CLI/Formatter.hpp"
#include <nlohmann/json.hpp>

int main(int argc, const char *argv[]) {
    using nlohmann::json;

    CLI::App app{""}; // message

    std::string issue_date;
    std::string expiry_date;
    std::string author;
    std::string version;
    std::string licensee;
    std::string filename;
    app.require_subcommand(1, 1);
    auto *generate_cmd = app.add_subcommand("generate");
    generate_cmd->add_option("-i,--issue-date", issue_date, "issue date");
    generate_cmd->add_option("-e,--expiry-date", expiry_date, "expiry date");
    generate_cmd->add_option("-a,--author", author, "authority")->required();
    generate_cmd->add_option("-v,--version", version, "version");
    generate_cmd->add_option("-l,--licensee", licensee, "licensee");
    generate_cmd->add_option("-f,--filename", filename, "filename");

    auto *verify_cmd = app.add_subcommand("verify");
    verify_cmd->add_option("-f,--filename", filename, "input filename")->required();

    CLI11_PARSE(app, argc, argv);

    json config;
    if (app.got_subcommand("generate")) {
        config["issue_date"] = issue_date;
        config["expiry_date"] = expiry_date;
        config["author"] = author;
        config["version"] = version;
        config["licensee"] = licensee;
        config["filename"] = filename;
        std::cout << config.dump(4) << std::endl;
        // handle_generate();
        return 0;
    }

    if (app.got_subcommand("verify")) {
        config["filename"] = filename;
        std::cout << config.dump(4) << std::endl;
        // handle_verify();
        return 0;
    }
    return 0;
}