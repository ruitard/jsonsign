find_package(jsoncpp CONFIG REQUIRED)

add_executable(licenseman licenseman.cpp)
target_link_libraries(licenseman PRIVATE licensecore JsonCpp::JsonCpp)