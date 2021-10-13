# cli11
find_package(CLI11 REQUIRED)

# json
find_package(nlohmann_json REQUIRED)

add_executable(licenseman licenseman.cpp)

target_link_libraries(licenseman
    PRIVATE licensecore
    PRIVATE CLI11::CLI11
    PRIVATE nlohmann_json::nlohmann_json
)
