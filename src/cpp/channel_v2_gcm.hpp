#pragma once
// Session-owned keyed EVP state. A new 96-bit sequence nonce is mandatory for
// every operation. Endpoint locking and nonce/replay policy remain above this.
#include "crypto.hpp"
#include <array>
#include <span>

namespace cr01::v2 {
class RecordCipher {
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx_{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};
    const bool encrypt_;
public:
    RecordCipher(std::span<const unsigned char> key, bool encrypt) : encrypt_(encrypt) {
        const std::array<unsigned char, 12> unused_iv{};
        if (key.size() != 32 || !ctx_ || EVP_CipherInit_ex(ctx_.get(), EVP_aes_256_gcm(), nullptr,
                key.data(), unused_iv.data(), encrypt_ ? 1 : 0) != 1)
            record::fail_openssl("v2 cipher setup failed");
    }
    RecordCipher(const RecordCipher&) = delete;
    RecordCipher& operator=(const RecordCipher&) = delete;
    RecordCipher(RecordCipher&&) = delete;
    RecordCipher& operator=(RecordCipher&&) = delete;
    bool is_encrypting() const noexcept { return encrypt_; }

    // No plaintext is exposed by callers until this returns successfully.
    void apply(std::span<const unsigned char, 12> iv, std::span<const unsigned char> header,
               std::span<const unsigned char> external, std::span<const unsigned char> input,
               std::span<unsigned char> output, std::span<unsigned char, 16> tag) {
        if (header.size() != 37 || external.size() > record::kMaxAadBytes
            || input.size() > record::kMaxPayloadBytes || output.size() < input.size() + 1)
            throw std::invalid_argument("v2 cipher input rejected");
        // Reinitialise even after failed authentication. Never reuse an old IV,
        // tag or partial record state. Key/cipher remain bound to this session.
        if (EVP_CipherInit_ex(ctx_.get(), nullptr, nullptr, nullptr, iv.data(), encrypt_ ? 1 : 0) != 1)
            record::fail_openssl("v2 cipher nonce setup failed");
        constexpr std::string_view domain = "CR01-SC-CHANNEL-v2";
        const unsigned char zero = 0;
        int n = 0, written = 0, tail = 0;
        const auto aad = [&](const unsigned char* data, std::size_t length) {
            if (length && EVP_CipherUpdate(ctx_.get(), nullptr, &n, data, static_cast<int>(length)) != 1)
                record::fail_openssl("v2 cipher AAD failed");
        };
        aad(reinterpret_cast<const unsigned char*>(domain.data()), domain.size());
        aad(&zero, 1); aad(header.data(), header.size()); aad(external.data(), external.size());
        if (!input.empty() && EVP_CipherUpdate(ctx_.get(), output.data(), &written, input.data(), static_cast<int>(input.size())) != 1)
            record::fail_openssl("v2 cipher payload failed");
        if (!encrypt_ && EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_GCM_SET_TAG, 16, tag.data()) != 1)
            record::fail_openssl("v2 cipher tag setup failed");
        if (EVP_CipherFinal_ex(ctx_.get(), output.data() + written, &tail) != 1)
            record::fail_openssl("v2 record authentication failed");
        if (static_cast<std::size_t>(written + tail) != input.size())
            record::fail_openssl("v2 cipher output length failed");
        if (encrypt_ && EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1)
            record::fail_openssl("v2 cipher tag retrieval failed");
    }
};
} // namespace cr01::v2
