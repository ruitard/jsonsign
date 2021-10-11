#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include "pk.hpp"
#include "error.hpp"

namespace licenseman {
namespace PK {

class Signer {
private:
    mbedtls_pk_context       pk;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    buffer                   pers;

public:
    Signer() noexcept {
        mbedtls_pk_init(&pk);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
    }
    explicit Signer(const buffer &pers) noexcept : Signer() { this->pers = pers; }

    void load_key(const buffer &private_key, const buffer &password = buffer()) {
        int err = 0;
        err = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, pers.data(), pers.size());
        handle_mbedtls_error(err);

        err = mbedtls_pk_parse_key(&pk, private_key.data(), private_key.size(), password.data(), password.size());
        handle_mbedtls_error(err);
    }

    void load_key(const fs::path &private_keyfile, const std::string &password = std::string()) {
        int err = 0;
        // TODO: 重复代码合并
        err = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, pers.data(), pers.size());
        handle_mbedtls_error(err);

        err = mbedtls_pk_parse_keyfile(&pk, private_keyfile.c_str(), password.c_str());
        handle_mbedtls_error(err);
    }

    buffer sign(const buffer &content) {
        // TODO: 验证 pk 有效性
        size_t        olen = 0;
        unsigned char hash[32]{};
        buffer        signature(MBEDTLS_PK_SIGNATURE_MAX_SIZE, 0);

        int err = 0;
        err = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), content.data(), content.size(), hash);
        handle_mbedtls_error(err);
        err = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 0, signature.data(), &olen, mbedtls_ctr_drbg_random,
                              &ctr_drbg);
        handle_mbedtls_error(err);

        signature.resize(olen);
        signature.shrink_to_fit();
        return std::move(signature);
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

    void load_key(const buffer &public_key) {
        int err = 0;
        err = mbedtls_pk_parse_public_key(&pk, public_key.data(), public_key.size());
        handle_mbedtls_error(err);
    }

    void load_key(const fs::path &public_keyfile) {
        int err = 0;
        err = mbedtls_pk_parse_public_keyfile(&pk, public_keyfile.c_str());
        handle_mbedtls_error(err);
    }

    bool verify(const buffer &content, const buffer &signature) {
        // TODO: 验证 pk 有效性
        int           err = 0;
        unsigned char hash[32]{};
        err = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), content.data(), content.size(), hash);
        handle_mbedtls_error(err);

        return (mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, 0, signature.data(), signature.size()) == 0);
    }

    ~Verifier() noexcept { mbedtls_pk_free(&pk); }
};

buffer sign(const buffer &content, const buffer &private_key, const buffer &password) {
    Signer signer;
    signer.load_key(private_key, password);
    return signer.sign(content);
}

buffer sign(const buffer &content, const fs::path &private_keyfile, const std::string &password) {
    Signer signer;
    signer.load_key(private_keyfile, password);
    return signer.sign(content);
}

bool verify(const buffer &content, const buffer &signature, const buffer &public_key) {
    Verifier verifier;
    verifier.load_key(public_key);
    return verifier.verify(content, signature);
}

bool verify(const buffer &content, const buffer &signature, const fs::path &public_keyfile) {
    Verifier verifier;
    verifier.load_key(public_keyfile);
    return verifier.verify(content, signature);
}

} // namespace PK
} // namespace licenseman