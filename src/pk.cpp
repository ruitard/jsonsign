#include <array>

#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include "keycore.hpp"
#include "helper.hpp"

namespace keycore::pk {

class Signer {
private:
    mbedtls_pk_context       pk;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

public:
    Signer() noexcept {
        mbedtls_pk_init(&pk);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
    }
    Signer(const Signer &) = delete;
    Signer(Signer &&) = delete;
    Signer &operator=(const Signer &) = delete;
    Signer &operator=(Signer &&) = delete;

    void load_key(const std::variant<fs::path, std::string_view> &private_key) {
        int err = 0;
        err = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0);
        HANDLE_MBEDTLS_ERROR(err);
        if (std::holds_alternative<fs::path>(private_key)) {
            err = mbedtls_pk_parse_keyfile(&pk, std::get<fs::path>(private_key).string().c_str(), nullptr);
        } else if (std::holds_alternative<std::string_view>(private_key)) {
            err = mbedtls_pk_parse_key(
                &pk, reinterpret_cast<const unsigned char *>(std::get<std::string_view>(private_key).data()),
                std::get<std::string_view>(private_key).length() + 1, nullptr, 0);
        }
        HANDLE_MBEDTLS_ERROR(err);
    }

    buffer sign(const buffer &content) {
        size_t                        olen = 0;
        std::array<unsigned char, 32> hash{};
        buffer                        signature(MBEDTLS_PK_SIGNATURE_MAX_SIZE, 0);

        int err = 0;
        err = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), content.data(), content.size(), hash.data());
        HANDLE_MBEDTLS_ERROR(err);
        err = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash.data(), 0, signature.data(), &olen, mbedtls_ctr_drbg_random,
                              &ctr_drbg);
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
    Verifier() noexcept { mbedtls_pk_init(&pk); }
    Verifier(const Verifier &) = delete;
    Verifier(Verifier &&) = delete;
    Verifier &operator=(const Verifier &) = delete;
    Verifier &operator=(Verifier &&) = delete;

    void load_key(const std::variant<fs::path, std::string_view> &public_key) {
        int err = 0;
        if (std::holds_alternative<fs::path>(public_key)) {
            err = mbedtls_pk_parse_public_keyfile(&pk, std::get<fs::path>(public_key).string().c_str());
        } else if (std::holds_alternative<std::string_view>(public_key)) {
            err = mbedtls_pk_parse_public_key(
                &pk, reinterpret_cast<const unsigned char *>(std::get<std::string_view>(public_key).data()),
                std::get<std::string_view>(public_key).length() + 1);
        }
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

buffer sign(const buffer &content, const std::variant<fs::path, std::string_view> &key) {
    Signer signer;
    signer.load_key(key);
    return signer.sign(content);
}

bool verify(const buffer &content, const buffer &signature, const std::variant<fs::path, std::string_view> &key) {
    Verifier verifier;
    verifier.load_key(key);
    return verifier.verify(content, signature);
}

class KeyPair {
private:
    mbedtls_pk_context       ctx;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    buffer                   key_buffer;

public:
    KeyPair() noexcept {
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

        key_buffer.resize(4096);
    }
    std::string gen_private_key() {
        int ret = mbedtls_pk_write_key_pem(&ctx, key_buffer.data(), key_buffer.size());
        HANDLE_MBEDTLS_ERROR(ret);
        return reinterpret_cast<char *>(key_buffer.data());
    }
    std::string gen_public_key() {
        int ret = mbedtls_pk_write_pubkey_pem(&ctx, key_buffer.data(), key_buffer.size());
        HANDLE_MBEDTLS_ERROR(ret);
        return reinterpret_cast<char *>(key_buffer.data());
    }
};

std::tuple<std::string, std::string> gen_key_pair(key_type type) {
    KeyPair kp;
    kp.setup(type);
    return {kp.gen_private_key(), kp.gen_public_key()};
}

} // namespace keycore::pk