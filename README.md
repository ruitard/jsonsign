# jsonsign

A tool for Json File Signing, Verification.

## 项目说明
`jsign` 是一个用来对 json 文件进行签名、校验的命令行工具，它具备以下特性：

- 基于 `RSA` 或 `ECDSA` 防止数据被篡改
- 只对 json 数据做校验，与 json 对象顺序无关
- 基于公开的数字签名认证体系，任何人都可以校验签名合法性
- 跨平台支持，支持 Linux 及 Windows
- 使用灵活方便，可以集成到库中，为您自己的软件提供授权服务

## 构建方式
### 编译环境要求
- 编译器需要支持 C++20
### 第三方依赖库
- [MbedTLS](https://github.com/ARMmbed/mbedtls)
- [nlohmann-json](https://github.com/nlohmann/json)
- [CLI11](https://github.com/CLIUtils/CLI11)
### 使用 CMake 构建
使用 [vcpkg](https://github.com/microsoft/vcpkg) 安装第三方依赖库
```shell
$ vcpkg install mbedtls cli11 nlohmann-json
```
编译
```shell
$ cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_TOOLCHAIN_FILE=/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake .

$ cmake --build build --target install --config RelWithDebInfo --parallel $(nproc)
```
### 快速上手
`jsign` 主要有三个功能：
- 生成密钥对
- 使用私钥对目标 json 文件签名，并将签名信息存储在 json 文件中
- 从 json 文件中读取签名信息，并根据公钥进行验证
#### 生成密钥对
```shell
$ jsign generate-key-pair
Private key written to jsign.key
Public key written to jsign.pub
```
#### 对 json 文件进行签名
目标 json 文件样例（license.json）:
```json
{
    "issue_date": "2010-12-16",
    "expiry_date": "2030-02-02",
    "issuing_authority": "sample-license-authority",
    "licensee": "john-citizen",
    "additional_payload": "xswl, yyds"
}
```
```shell
$ jsign sign --key jsign.key --file license.json
{
    "additional_payload": "xswl, yyds",
    "expiry_date": "2030-02-02",
    "issue_date": "2010-12-16",
    "issuing_authority": "sample-license-authority",
    "licensee": "john-citizen",
    "|signature|": "MIGHAkIBwxKw7DB2PqW1gyq3kEbjuqd7LOoQisglTDxYiLmBSHWxNXOGYXfX+7h7iONii+tZXGc0Vl6FD90HW7glGK6E694CQVX4hbXNCh8jLvEn3vhF8NWN1gjsuVXPMaO8+VWJGMH0o+MMIZswIr/BRzaZpLvGAFm5piT1fnKCr4L/Q+CGOZaO"
}
```
#### 验证已签名的 json 文件
```shell
$ jsign verify --key jsign.pub --file license.json
The signature were verified against the specified public key
```