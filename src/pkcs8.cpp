#include "pkcs8.hpp"

#include <array>
#include <cstring>
#include <span>

#include <mbedtls/asn1write.h>
#include <mbedtls/oid.h>
#include <mbedtls/pem.h>
#include <mbedtls/pkcs5.h>

#include "helper.hpp"

namespace keycore::pk {
namespace {

constexpr std::size_t key_capacity = 16384;
constexpr int iterations = 600000;
// id-aes256-CBC, RFC 8018 Appendix B.2.5.
constexpr std::string_view aes256_cbc_oid{"\x60\x86\x48\x01\x65\x03\x04\x01\x2a", 9};

class der_writer {
    secure_buffer storage_{key_capacity};
    unsigned char *end_ = storage_.data() + storage_.size();
    unsigned char *pos_ = end_;

    void check(int result) {
        if (result < 0) {
            HANDLE_MBEDTLS_ERROR(result);
        }
    }

  public:
    std::size_t size() const { return static_cast<std::size_t>(end_ - pos_); }
    std::span<const unsigned char> bytes() const { return {pos_, size()}; }
    void raw(std::span<const unsigned char> value) {
        check(mbedtls_asn1_write_raw_buffer(&pos_, storage_.data(), value.data(), value.size()));
    }
    void octets(std::span<const unsigned char> value) {
        check(mbedtls_asn1_write_octet_string(&pos_, storage_.data(), value.data(), value.size()));
    }
    void integer(int value) { check(mbedtls_asn1_write_int(&pos_, storage_.data(), value)); }
    void oid(std::string_view value) {
        check(mbedtls_asn1_write_oid(&pos_, storage_.data(), value.data(), value.size()));
    }
    void algorithm(std::string_view value, std::size_t parameter_size = 0) {
        check(mbedtls_asn1_write_algorithm_identifier(&pos_, storage_.data(), value.data(), value.size(),
                                                      parameter_size));
    }
    void sequence(std::size_t length) {
        check(mbedtls_asn1_write_len(&pos_, storage_.data(), length));
        check(mbedtls_asn1_write_tag(&pos_, storage_.data(), MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    }
};

} // namespace

secure_buffer export_private_key(const mbedtls_pk_context &key, std::string_view password,
                                 mbedtls_ctr_drbg_context &rng) {
    secure_buffer pem(key_capacity * 2);
    if (password.empty()) {
        HANDLE_MBEDTLS_ERROR(mbedtls_pk_write_key_pem(&key, pem.data(), pem.size()));
        pem.resize(std::strlen(reinterpret_cast<const char *>(pem.data())));
        return pem;
    }
    // The library callers' buffers are borrowed; protect our own password copy.
    secure_buffer protected_password(password);
    secure_buffer raw_key(key_capacity);
    const int written = mbedtls_pk_write_key_der(&key, raw_key.data(), raw_key.size());
    if (written < 0) {
        HANDLE_MBEDTLS_ERROR(written);
    }

    // Wrap PKCS#1 / SEC1 in the standard PKCS#8 PrivateKeyInfo structure.
    der_writer private_info;
    private_info.octets({raw_key.data() + raw_key.size() - written, static_cast<std::size_t>(written)});
    if (mbedtls_pk_get_type(&key) == MBEDTLS_PK_RSA) {
        private_info.algorithm(MBEDTLS_OID_PKCS1_RSA);
    } else if (mbedtls_pk_get_type(&key) == MBEDTLS_PK_ECKEY) {
        const char *curve_oid = nullptr;
        std::size_t curve_size = 0;
        HANDLE_MBEDTLS_ERROR(mbedtls_oid_get_oid_by_ec_grp(mbedtls_ecp_keypair_get_group_id(mbedtls_pk_ec(key)),
                                                           &curve_oid, &curve_size));
        const auto before = private_info.size();
        private_info.oid({curve_oid, curve_size});
        private_info.algorithm(MBEDTLS_OID_EC_ALG_UNRESTRICTED, private_info.size() - before);
    } else {
        throw std::runtime_error("Encrypted export supports RSA and named-curve EC keys");
    }
    private_info.integer(0);
    private_info.sequence(private_info.size());

    std::array<unsigned char, 16> salt{}, iv{};
    HANDLE_MBEDTLS_ERROR(mbedtls_ctr_drbg_random(&rng, salt.data(), salt.size()));
    HANDLE_MBEDTLS_ERROR(mbedtls_ctr_drbg_random(&rng, iv.data(), iv.size()));

    // PBES2: PBKDF2-HMAC-SHA256, a fresh 128-bit salt, AES-256-CBC / PKCS#7.
    der_writer parameters;
    parameters.octets(iv);
    parameters.algorithm(aes256_cbc_oid, parameters.size());
    const auto encryption_scheme_size = parameters.size();
    parameters.algorithm(MBEDTLS_OID_HMAC_SHA256);
    parameters.integer(iterations);
    parameters.octets(salt);
    parameters.sequence(parameters.size() - encryption_scheme_size);
    parameters.algorithm(MBEDTLS_OID_PKCS5_PBKDF2, parameters.size() - encryption_scheme_size);
    parameters.sequence(parameters.size());

    auto encoded_parameters = parameters.bytes();
    auto *cursor = const_cast<unsigned char *>(encoded_parameters.data());
    mbedtls_asn1_buf parsed_parameters{};
    parsed_parameters.tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;
    HANDLE_MBEDTLS_ERROR(mbedtls_asn1_get_tag(&cursor, cursor + encoded_parameters.size(), &parsed_parameters.len,
                                              parsed_parameters.tag));
    parsed_parameters.p = cursor;

    secure_buffer encrypted(key_capacity);
    std::size_t encrypted_size = 0;
    const auto private_bytes = private_info.bytes();
    HANDLE_MBEDTLS_ERROR(mbedtls_pkcs5_pbes2_ext(&parsed_parameters, MBEDTLS_PKCS5_ENCRYPT, protected_password.data(),
                                                 protected_password.size(), private_bytes.data(), private_bytes.size(),
                                                 encrypted.data(), encrypted.size(), &encrypted_size));

    der_writer envelope;
    envelope.octets({encrypted.data(), encrypted_size});
    envelope.raw(encoded_parameters);
    envelope.algorithm(MBEDTLS_OID_PKCS5_PBES2, encoded_parameters.size());
    envelope.sequence(envelope.size());
    const auto der = envelope.bytes();
    std::size_t pem_size = 0;
    HANDLE_MBEDTLS_ERROR(mbedtls_pem_write_buffer("-----BEGIN ENCRYPTED PRIVATE KEY-----\n",
                                                  "-----END ENCRYPTED PRIVATE KEY-----\n", der.data(), der.size(),
                                                  pem.data(), pem.size(), &pem_size));
    pem.resize(pem_size - 1);
    return pem;
}

} // namespace keycore::pk
