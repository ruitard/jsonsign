#include <array>

#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include "keycore.hpp"
#include "helper.hpp"
#include "pkcs8.hpp"
#include "secure_io.hpp"
#include "secure_call.hpp"

namespace keycore::pk {

class Signer {
private:
    mbedtls_pk_context       pk;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

public:
    Signer() {
        initialize_secure_memory();
        mbedtls_pk_init(&pk);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
    }
    Signer(const Signer &) = delete;
    Signer(Signer &&) = delete;
    Signer &operator=(const Signer &) = delete;
    Signer &operator=(Signer &&) = delete;

    void load_key(const fs::path &private_keyfile, std::string_view password) {
        auto key = read_secret_file(private_keyfile);
        load_key(key.view(), password);
    }
    void load_key(std::string_view private_key, std::string_view password) {
        secure_buffer key(private_key);
        secure_buffer passphrase(password);
        HANDLE_MBEDTLS_ERROR(mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0));
        const auto *pwd = passphrase.empty() ? nullptr : passphrase.data();
        const auto key_size = key.size() + (key.view().starts_with("-----BEGIN ") ? 1 : 0);
        const int result = mbedtls_pk_parse_key(&pk, key.data(), key_size, pwd, passphrase.size(),
                                                mbedtls_ctr_drbg_random, &ctr_drbg);
        if (result == MBEDTLS_ERR_PK_PASSWORD_REQUIRED) {
            throw password_required();
        }
        HANDLE_MBEDTLS_ERROR(result);
    }

    secure_buffer encrypt(std::string_view password) {
        if (password.empty()) throw std::runtime_error("An encryption passphrase is required");
        return export_private_key(pk, password, ctr_drbg);
    }

    buffer sign(const buffer &content) {
        size_t                        olen = 0;
        std::array<unsigned char, 32> hash{};
        buffer                        signature(MBEDTLS_PK_SIGNATURE_MAX_SIZE, 0);

        int err = 0;
        err = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), content.data(), content.size(), hash.data());
        HANDLE_MBEDTLS_ERROR(err);
        err = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash.data(), hash.size(), signature.data(), signature.size(),
                              &olen, mbedtls_ctr_drbg_random, &ctr_drbg);
        HANDLE_MBEDTLS_ERROR(err);

        signature.resize(olen);
        signature.shrink_to_fit();
        return signature;
    }

    ~Signer() noexcept {
        mbedtls_pk_free(&pk);
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
    }
};

class Verifier {
private:
    mbedtls_pk_context pk;

public:
    Verifier() {
        initialize_secure_memory();
        mbedtls_pk_init(&pk);
    }
    Verifier(const Verifier &) = delete;
    Verifier(Verifier &&) = delete;
    Verifier &operator=(const Verifier &) = delete;
    Verifier &operator=(Verifier &&) = delete;

    void load_key(const fs::path &public_keyfile) {
        int err = mbedtls_pk_parse_public_keyfile(&pk, public_keyfile.string().c_str());
        HANDLE_MBEDTLS_ERROR(err);
    }
    void load_key(const std::string_view &public_key) {
        const std::string key(public_key);
        const auto size = key.size() + (key.starts_with("-----BEGIN ") ? 1 : 0);
        int err = mbedtls_pk_parse_public_key(&pk, reinterpret_cast<const unsigned char *>(key.data()), size);
        HANDLE_MBEDTLS_ERROR(err);
    }

    bool verify(const buffer &content, const buffer &signature) {
        std::array<unsigned char, 32> hash{};

        int err = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), content.data(), content.size(), hash.data());
        HANDLE_MBEDTLS_ERROR(err);

        return (mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash.data(), 0, signature.data(), signature.size()) == 0);
    }

    ~Verifier() noexcept { mbedtls_pk_free(&pk); }
};

buffer sign(const buffer &content, const fs::path &key_file, std::string_view password) {
    return detail::secure_call([&] {
        Signer signer;
        signer.load_key(key_file, password);
        return signer.sign(content);
    });
}
buffer sign(const buffer &content, const std::string_view &key, std::string_view password) {
    return detail::secure_call([&] {
        Signer signer;
        signer.load_key(key, password);
        return signer.sign(content);
    });
}

bool verify(const buffer &content, const buffer &signature, const std::string_view &key) {
    Verifier verifier;
    verifier.load_key(key);
    return verifier.verify(content, signature);
}
bool verify(const buffer &content, const buffer &signature, const fs::path &key_file) {
    Verifier verifier;
    verifier.load_key(key_file);
    return verifier.verify(content, signature);
}

class KeyPair {
private:
    mbedtls_pk_context       ctx;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

public:
    KeyPair() {
        initialize_secure_memory();
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_pk_init(&ctx);
        mbedtls_entropy_init(&entropy);
    }
    KeyPair(const KeyPair &) = delete;
    KeyPair(KeyPair &&) = delete;
    KeyPair &operator=(const KeyPair &) = delete;
    KeyPair &operator=(KeyPair &&) = delete;
    ~KeyPair() noexcept {
        mbedtls_pk_free(&ctx);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
    }
    void setup(key_type type = key_type::ECKEY) {
        int ret = 0;
        ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0);
        HANDLE_MBEDTLS_ERROR(ret);

        switch (type) {
        case key_type::RSA:
            ret = mbedtls_pk_setup(&ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
            HANDLE_MBEDTLS_ERROR(ret);
            ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(ctx), mbedtls_ctr_drbg_random, &ctr_drbg, 4096, 65537);
            HANDLE_MBEDTLS_ERROR(ret);
            break;
        case key_type::ECKEY:
            ret = mbedtls_pk_setup(&ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
            HANDLE_MBEDTLS_ERROR(ret);
            ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP521R1, mbedtls_pk_ec(ctx), mbedtls_ctr_drbg_random, &ctr_drbg);
            HANDLE_MBEDTLS_ERROR(ret);
            break;
        default: throw std::runtime_error("wrong key type");
        }
    }
    secure_buffer gen_private_key(std::string_view password) {
        return export_private_key(ctx, password, ctr_drbg);
    }
    std::string gen_public_key() {
        buffer key_buffer(4096);
        HANDLE_MBEDTLS_ERROR(mbedtls_pk_write_pubkey_pem(&ctx, key_buffer.data(), key_buffer.size()));
        return reinterpret_cast<const char *>(key_buffer.data());
    }
};

std::tuple<secure_buffer, std::string> gen_key_pair(key_type type, std::string_view password) {
    return detail::secure_call([&]() -> std::tuple<secure_buffer, std::string> {
        KeyPair kp;
        kp.setup(type);
        return {kp.gen_private_key(password), kp.gen_public_key()};
    });
}

secure_buffer encrypt_private_key(std::string_view key, std::string_view password) {
    return detail::secure_call([&] {
        Signer signer;
        signer.load_key(key, {});
        return signer.encrypt(password);
    });
}

} // namespace keycore::pk
