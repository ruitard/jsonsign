#include <array>

#include <mbedtls/pk.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include "pk.hpp"
#include "error.hpp"

namespace licenseman::pk {

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

    void load_key(const fs::path &private_keyfile) {
        int err = 0;
        err = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0);
        handle_mbedtls_error(err);
        err = mbedtls_pk_parse_keyfile(&pk, private_keyfile.c_str(), nullptr);
        handle_mbedtls_error(err);
    }

    buffer sign(const buffer &content) {
        size_t                        olen = 0;
        std::array<unsigned char, 32> hash{};
        buffer                        signature(MBEDTLS_PK_SIGNATURE_MAX_SIZE, 0);

        int err = 0;
        err = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), content.data(), content.size(), hash.data());
        handle_mbedtls_error(err);
        err = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash.data(), 0, signature.data(), &olen, mbedtls_ctr_drbg_random,
                              &ctr_drbg);
        handle_mbedtls_error(err);

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

    void load_key(const fs::path &public_keyfile) {
        int err = mbedtls_pk_parse_public_keyfile(&pk, public_keyfile.c_str());
        handle_mbedtls_error(err);
    }

    bool verify(const buffer &content, const buffer &signature) {
        std::array<unsigned char, 32> hash{};

        int err = mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), content.data(), content.size(), hash.data());
        handle_mbedtls_error(err);

        return (mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash.data(), 0, signature.data(), signature.size()) == 0);
    }

    ~Verifier() noexcept { mbedtls_pk_free(&pk); }
};

buffer sign(const buffer &content, const fs::path &private_keyfile) {
    Signer signer;
    signer.load_key(private_keyfile);
    return signer.sign(content);
}

bool verify(const buffer &content, const buffer &signature, const fs::path &public_keyfile) {
    Verifier verifier;
    verifier.load_key(public_keyfile);
    return verifier.verify(content, signature);
}

namespace rsa {

void gen_key_pair(std::string &key, std::string &public_key) {
    mbedtls_pk_context       pk;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);

    int ret = 0;
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, nullptr, 0);
    handle_mbedtls_error(ret);

    ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    handle_mbedtls_error(ret);

    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk), mbedtls_ctr_drbg_random, &ctr_drbg, 4096, 65537);
    handle_mbedtls_error(ret);

    buffer key_buffer(4096, 0);
    ret = mbedtls_pk_write_key_pem(&pk, key_buffer.data(), key_buffer.size());
    handle_mbedtls_error(ret);
    key = std::string(reinterpret_cast<char *>(key_buffer.data()));

    ret = mbedtls_pk_write_pubkey_pem(&pk, key_buffer.data(), key_buffer.size());
    handle_mbedtls_error(ret);
    public_key = std::string(reinterpret_cast<char *>(key_buffer.data()));

    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}
} // namespace rsa

} // namespace licenseman::pk