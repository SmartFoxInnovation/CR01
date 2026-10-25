// Build prerequisite probe only: algorithm availability is not a security test.
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/opensslv.h>
#include <iostream>

// Release snapshot floors, not an ongoing vulnerability scan or security proof.
constexpr bool patched_snapshot(unsigned long version) {
    return (version >= 0x30500090L && version < 0x30600000L) ||
           (version >= 0x30600050L && version < 0x40000000L) ||
           (version >= 0x40000030L && version < 0x50000000L);
}
static_assert(patched_snapshot(OPENSSL_VERSION_NUMBER),
              "Use patched OpenSSL headers: 3.5.9+, 3.6.5+ or 4.0.3+; see docs/GUIDE.md");

int main() {
    if (!patched_snapshot(OpenSSL_version_num())) {
        std::cerr << "OpenSSL runtime is below this release's patched snapshot; see docs/GUIDE.md\n";
        return 1;
    }
    bool available = true;
    for (const auto* name : {"ML-KEM-768", "ML-DSA-65"}) {
        auto* context = EVP_PKEY_CTX_new_from_name(nullptr, name, nullptr);
        if (!context) { std::cerr << "OpenSSL algorithm unavailable: " << name << '\n'; available = false; }
        EVP_PKEY_CTX_free(context);
    }
    auto* cipher = EVP_CIPHER_fetch(nullptr, "AES-256-GCM", nullptr);
    auto* digest = EVP_MD_fetch(nullptr, "SHA256", nullptr);
    auto* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    available = available && cipher && digest && kdf;
    EVP_CIPHER_free(cipher);
    EVP_MD_free(digest);
    EVP_KDF_free(kdf);
    if (!available) { std::cerr << "Required OpenSSL algorithms are unavailable\n"; return 1; }
    std::cout << OpenSSL_version(OPENSSL_VERSION) << ": required algorithms available\n";
    return 0;
}
