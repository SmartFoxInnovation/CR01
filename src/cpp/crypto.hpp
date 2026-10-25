#pragma once

// Shared backend crypto utilities. No legacy record format or session policy.
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <span>
#include <utility>
#include <vector>

namespace cr01::record {

using Bytes = std::vector<std::uint8_t>;

constexpr std::size_t kKeyBytes = 32;
constexpr std::size_t kNonceBytes = 12;
constexpr std::size_t kTagBytes = 16;
constexpr std::size_t kMaxPayloadBytes = 8 * 1024 * 1024;
constexpr std::size_t kMaxAadBytes = 64 * 1024;

struct WipeOnExit {
    Bytes& value;
    ~WipeOnExit() { if (!value.empty()) OPENSSL_cleanse(value.data(), value.size()); }
    WipeOnExit(const WipeOnExit&) = delete;
    WipeOnExit& operator=(const WipeOnExit&) = delete;
    explicit WipeOnExit(Bytes& bytes) : value(bytes) {}
};

[[noreturn]] inline void fail_openssl(const std::string& message) {
    throw std::runtime_error(message);
}

inline Bytes ascii_bytes(std::string_view value) {
    return Bytes(value.begin(), value.end());
}

inline void append(Bytes& out, const Bytes& value) {
    out.insert(out.end(), value.begin(), value.end());
}

inline void append(Bytes& out, std::string_view value) {
    out.insert(out.end(), value.begin(), value.end());
}

inline Bytes uint64_be(std::uint64_t value) {
    Bytes out(8);
    for (int index = 7; index >= 0; --index) {
        out[static_cast<std::size_t>(index)] = static_cast<std::uint8_t>(value & 0xffU);
        value >>= 8U;
    }
    return out;
}

inline Bytes sha256(const Bytes& data) {
    Bytes digest(EVP_MAX_MD_SIZE);
    unsigned int length = 0;
    if (EVP_Digest(data.data(), data.size(), digest.data(), &length, EVP_sha256(), nullptr) != 1) {
        fail_openssl("EVP_Digest(SHA-256) failed");
    }
    digest.resize(length);
    return digest;
}

inline Bytes hmac_sha256(std::span<const std::uint8_t> key, std::span<const std::uint8_t> data) {
    if (key.size() > kMaxPayloadBytes) {
        throw std::invalid_argument("HMAC key exceeds input limit");
    }
    Bytes mac(EVP_MAX_MD_SIZE);
    unsigned int length = 0;
    if (HMAC(
            EVP_sha256(),
            key.data(),
            static_cast<int>(key.size()),
            data.data(),
            data.size(),
            mac.data(),
            &length) == nullptr) {
        fail_openssl("HMAC-SHA256 failed");
    }
    mac.resize(length);
    return mac;
}

inline Bytes hkdf_sha256(const Bytes& ikm, const Bytes& salt, const Bytes& info, std::size_t length) {
    if (length == 0 || length > 255 * 32) {
        throw std::invalid_argument("HKDF output length outside SHA-256 bounds");
    }
    Bytes prk = hmac_sha256(salt, ikm);
    WipeOnExit wipe_prk(prk);
    Bytes output;
    Bytes previous;
    WipeOnExit wipe_previous(previous);
    std::uint8_t counter = 1;
    while (output.size() < length) {
        Bytes block_input;
        append(block_input, previous);
        append(block_input, info);
        block_input.push_back(counter);
        previous = hmac_sha256(prk, block_input);
        append(output, previous);
        ++counter;
        if (counter == 0 && output.size() < length) {
            throw std::runtime_error("HKDF output length too large");
        }
    }
    output.resize(length);
    return output;
}

inline std::pair<Bytes, Bytes> aes_gcm_encrypt(const Bytes& key, const Bytes& nonce, const Bytes& plaintext, const Bytes& aad) {
    if (plaintext.size() > kMaxPayloadBytes || aad.size() > kMaxAadBytes + 128) {
        throw std::invalid_argument("record payload or AAD exceeds input limit");
    }
    if (key.size() != kKeyBytes) {
        throw std::invalid_argument("AES-256-GCM key must be 32 bytes");
    }
    if (nonce.size() != kNonceBytes) {
        throw std::invalid_argument("AES-GCM nonce must be 12 bytes");
    }

    EVP_CIPHER_CTX* raw_ctx = EVP_CIPHER_CTX_new();
    if (raw_ctx == nullptr) {
        fail_openssl("EVP_CIPHER_CTX_new failed");
    }
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(raw_ctx, EVP_CIPHER_CTX_free);

    int out_len = 0;
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        fail_openssl("EVP_EncryptInit_ex failed");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1) {
        fail_openssl("EVP_CTRL_GCM_SET_IVLEN failed");
    }
    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
        fail_openssl("EVP_EncryptInit_ex key/nonce failed");
    }
    if (!aad.empty() && EVP_EncryptUpdate(ctx.get(), nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1) {
        fail_openssl("EVP_EncryptUpdate AAD failed");
    }

    // AAD update may set out_len even though it produced no payload bytes.
    out_len = 0;
    Bytes ciphertext(plaintext.size() + EVP_CIPHER_get_block_size(EVP_aes_256_gcm()));
    if (!plaintext.empty()
        && EVP_EncryptUpdate(
               ctx.get(),
               ciphertext.data(),
               &out_len,
               plaintext.data(),
               static_cast<int>(plaintext.size()))
               != 1) {
        fail_openssl("EVP_EncryptUpdate plaintext failed");
    }
    int total_len = out_len;
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + total_len, &out_len) != 1) {
        fail_openssl("EVP_EncryptFinal_ex failed");
    }
    total_len += out_len;
    ciphertext.resize(static_cast<std::size_t>(total_len));

    Bytes tag(kTagBytes);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
        fail_openssl("EVP_CTRL_GCM_GET_TAG failed");
    }
    return {ciphertext, tag};
}

inline Bytes aes_gcm_decrypt(const Bytes& key, const Bytes& nonce, const Bytes& ciphertext, const Bytes& tag, const Bytes& aad) {
    if (ciphertext.size() > kMaxPayloadBytes || aad.size() > kMaxAadBytes + 128) {
        throw std::invalid_argument("record ciphertext or AAD exceeds input limit");
    }
    if (key.size() != kKeyBytes) {
        throw std::invalid_argument("AES-256-GCM key must be 32 bytes");
    }
    if (nonce.size() != kNonceBytes) {
        throw std::invalid_argument("AES-GCM nonce must be 12 bytes");
    }
    if (tag.size() != kTagBytes) {
        throw std::invalid_argument("AES-GCM tag must be 16 bytes");
    }

    EVP_CIPHER_CTX* raw_ctx = EVP_CIPHER_CTX_new();
    if (raw_ctx == nullptr) {
        fail_openssl("EVP_CIPHER_CTX_new failed");
    }
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(raw_ctx, EVP_CIPHER_CTX_free);

    int out_len = 0;
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        fail_openssl("EVP_DecryptInit_ex failed");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1) {
        fail_openssl("EVP_CTRL_GCM_SET_IVLEN failed");
    }
    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1) {
        fail_openssl("EVP_DecryptInit_ex key/nonce failed");
    }
    if (!aad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &out_len, aad.data(), static_cast<int>(aad.size())) != 1) {
        fail_openssl("EVP_DecryptUpdate AAD failed");
    }

    out_len = 0;
    Bytes plaintext(ciphertext.size() + EVP_CIPHER_get_block_size(EVP_aes_256_gcm()));
    if (!ciphertext.empty()
        && EVP_DecryptUpdate(
               ctx.get(),
               plaintext.data(),
               &out_len,
               ciphertext.data(),
               static_cast<int>(ciphertext.size()))
               != 1) {
        fail_openssl("EVP_DecryptUpdate ciphertext failed");
    }
    int total_len = out_len;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag.size()), const_cast<std::uint8_t*>(tag.data())) != 1) {
        fail_openssl("EVP_CTRL_GCM_SET_TAG failed");
    }
    if (EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + total_len, &out_len) != 1) {
        if (!plaintext.empty()) OPENSSL_cleanse(plaintext.data(), plaintext.size());
        throw std::runtime_error("AES-GCM authentication tag mismatch");
    }
    total_len += out_len;
    plaintext.resize(static_cast<std::size_t>(total_len));
    return plaintext;
}

} // namespace cr01::record
