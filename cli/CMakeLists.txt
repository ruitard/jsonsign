find_package(CLI11 REQUIRED)

find_package(nlohmann_json CONFIG REQUIRED)

add_executable(licenseman licenseman.cpp)
target_precompile_headers(licenseman
PRIVATE
    <iostream>
    <CLI/App.hpp>
    <CLI/Config.hpp>
    <CLI/Formatter.hpp>
    <nlohmann/json.hpp>
)

target_link_libraries(licenseman
    PRIVATE licensecore
    PRIVATE CLI11::CLI11
    PRIVATE nlohmann_json::nlohmann_json
)

install(TARGETS licenseman)