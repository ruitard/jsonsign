find_package(CLI11 CONFIG REQUIRED)

find_package(nlohmann_json CONFIG REQUIRED)

add_executable(jsign json_sign.cpp)

target_link_libraries(jsign
PRIVATE
    keycore
    CLI11::CLI11
    nlohmann_json::nlohmann_json
)

install(TARGETS jsign)