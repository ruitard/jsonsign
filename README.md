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
- 支持 C++20 的编译器
- CMake >= 3.24、Ninja、Git 和 vcpkg
### 第三方依赖库
- [MbedTLS](https://github.com/Mbed-TLS/mbedtls)
- [nlohmann-json](https://github.com/nlohmann/json)
- [CLI11](https://github.com/CLIUtils/CLI11)
- [libsodium](https://libsodium.org/)（敏感内存管理）

测试通过 CTest 运行；安装 OpenSSL 命令行工具后，会同时检查密钥与签名的互操作性。
MbedTLS 使用 vcpkg 官方 port，通过 `pthreads` feature 启用线程支持。
项目提供的 x64 Linux/Windows triplet 自动加载 [MbedTLS 配置](cmake/triplets/mbedtls.cmake)，通过 `MBEDTLS_USER_CONFIG_FILE` 启用安全内存分配所需的 `MBEDTLS_PLATFORM_MEMORY`，配置头文件随依赖安装。
使用其他 triplet 时，也需在其配置中包含该文件。

### 使用 CMake 构建
设置已有的 [vcpkg](https://github.com/microsoft/vcpkg) 路径；CMake 配置时会自动安装清单中的依赖：
```shell
export VCPKG_ROOT=/path/to/vcpkg
cmake --preset dev
cmake --build --preset dev --parallel
ctest --preset dev
./build/dev/cli/jsign --help
```

发布构建和本地安装：
```shell
cmake --preset release
cmake --build --preset release --parallel
ctest --preset release
cmake --install build/release
./build/release/installed/jsign --help
```

两个预设共用 `build/vcpkg_installed` 中的依赖，调试构建导出 `compile_commands.json`。

也可直接配置 CMake（Windows 可使用此方式选择 Visual Studio 生成器）：
```shell
cmake -S . -B build/manual -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake"
cmake --build build/manual --config RelWithDebInfo --parallel
ctest --test-dir build/manual -C RelWithDebInfo --output-on-failure
```
### 快速上手
`jsign` 主要有三个功能：
- 生成密钥对
- 使用私钥对目标 json 文件签名，并将签名信息存储在 json 文件中
- 从 json 文件中读取签名信息，并根据公钥进行验证
#### 生成密钥对
默认生成密码加密的 PKCS#8 私钥，输入密码时不回显，并要求再次确认。输出文件已存在时会报错。
```shell
$ jsign generate-key-pair
Passphrase:
Confirm passphrase:
Private key written to jsign.key
Public key written to jsign.pub
```

使用 `--type rsa` 生成 RSA 密钥；默认使用 ECDSA。通过 `--private-key`、`--public-key` 指定输出路径。
确需未加密私钥时，显式使用 `jsign generate-key-pair --no-passphrase`。

#### 加密已有私钥
```shell
jsign encrypt-key --key old.key --output encrypted.key
```

输入文件应为未加密的 RSA/EC 私钥。命令生成新的加密文件，原文件保留；确认新文件可用后，
由密钥所有者处理原明文文件及其备份。

#### 对 json 文件进行签名
使用加密私钥时会提示输入密码；原有未加密私钥也可直接使用。
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

### 自动化使用
生成、加密和签名命令均支持 `--passphrase-file` 或 `--passphrase-fd`，两者互斥。
密码取第一行，支持 1 至 1024 字节，不允许 NUL。密码文件在 Unix 上必须归当前用户所有，
且其他用户无访问权限（例如 `0600`）；密钥和密码文件均须为普通文件，不接受符号链接。

```shell
jsign generate-key-pair --passphrase-file /run/secrets/jsign-passphrase
jsign sign --key jsign.key --file license.json --passphrase-file /run/secrets/jsign-passphrase
# 也可由秘密管理服务通过文件描述符 3 提供密码
jsign sign --key jsign.key --file license.json --passphrase-fd 3
```

没有终端时必须显式提供密码来源。工具不接受命令行明文密码或密码环境变量。
自动化部署应由秘密管理服务注入口令，避免将密码文件与私钥一同归档。
新私钥文件在 Unix 上以 `0600` 创建，Windows 使用仅所有者和 SYSTEM 可访问的 DACL。

### 内存与密钥保护
私钥文件使用标准 PKCS#8 PBES2：AES-256-CBC、PBKDF2-HMAC-SHA256（600,000 次），
每次导出生成新的 16 字节盐和 IV。格式依据 [RFC 8018](https://www.rfc-editor.org/rfc/rfc8018.html)，
可由 OpenSSL 等工具读取。请使用足够长、不可预测的密码；CBC 加密本身不提供认证标签，
仍需保护密钥文件的来源、权限和备份。

私钥、密码和 MbedTLS 堆分配使用 [libsodium 安全内存](https://doc.libsodium.org/memory_management)：
锁页、保护页、释放时清零；锁页失败即停止操作。Linux 还排除这些映射的 core dump，
私钥操作使用独立的锁页栈，结束后整栈清零。CLI 的私钥命令禁用 core dump 和普通进程转储访问。
Windows 使用 VirtualLock 和 WER 内存排除，但不提供 Linux 的独立锁页栈；Windows 分支需在目标系统验证。
libsodium 仅提供敏感内存管理；密钥生成、RSA/ECDSA 签名验签及 PKCS#8 私钥加密由 MbedTLS 完成。
生产密钥应使用常规构建处理；内存诊断工具可能创建额外的数据副本，仅用于测试。

嵌入库时，`gen_key_pair` 返回的私钥为不可复制的 `secure_buffer`，通过 `.view()` 借用其内容，
不要将明文复制到普通 `std::string`。`sign` 的第三个参数、`gen_key_pair` 的第二个参数接受密码；
库接口密码为空时仍可处理未加密私钥。借用的输入由调用方负责保护。
在创建其他 MbedTLS 对象前调用 `initialize_secure_memory()`；分配器设置是进程全局的，不能与其他自定义分配器混用。
不要在持有敏感缓冲区时 `fork()`；子进程不会继承父进程的内存锁。
宿主程序可显式调用 `disable_process_dumps()` 应用进程级转储限制，库不会自行改变宿主的调试策略。

这些措施减少换页、转储和内存残留风险；使用中的私钥仍是明文，不能抵御已控制签名进程或内核的攻击者，
也不能保证阻止系统休眠镜像、内核转储或管理员导出的完整内存。生产环境还应采用加密磁盘/交换空间、
独立签名账号、最小权限、可信公钥分发，以及密钥轮换与撤销策略。

对高价值签名，更强的方案是将私钥生成并保存在不可导出的 HSM/TPM 或托管 KMS 中，应用只提交待签名摘要，
配合独立授权和审计。例如 [AWS KMS 非对称密钥](https://docs.aws.amazon.com/kms/latest/developerguide/symmetric-asymmetric.html)
通过服务调用使用私钥，可单独分发公钥验签。本项目当前使用文件密钥，尚未提供这些设备或服务的签名后端。
