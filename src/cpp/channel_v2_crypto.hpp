#pragma once
// OpenSSL-backed v2 operations and explicit identity files. No traffic-key IO.
#include "crypto.hpp"
#include "channel_v2_identity.hpp"
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <string_view>
#include <span>
#include <array>
#include <algorithm>
#ifdef _WIN32
#include <windows.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#else
#include <unistd.h>
#include <fcntl.h>
#endif

namespace cr01::channel {
using record::Bytes;
using Secret = memory::Secret;
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using KeyContext = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using DigestContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

[[noreturn]] inline void reject() { throw std::invalid_argument("v2 request rejected"); }
inline Bytes bytes(const std::string& text) { return Bytes(text.begin(), text.end()); }
inline std::string text(const Bytes& value) { return std::string(value.begin(), value.end()); }
inline const Bytes& domain() {
    static const Bytes value = [] { auto d = bytes("CR01-SC-HANDSHAKE-v2"); d.push_back(0); return d; }();
    return value;
}
inline std::uint64_t process_id() {
#ifdef _WIN32
    return GetCurrentProcessId();
#else
    return static_cast<std::uint64_t>(getpid());
#endif
}
inline Bytes packed(std::initializer_list<Bytes> values) {
    Bytes result;
    std::size_t size = 0;
    for (const auto& value : values) {
        if (value.size() > std::numeric_limits<std::uint32_t>::max()
            || value.size() > std::numeric_limits<std::size_t>::max() - 4
            || size > std::numeric_limits<std::size_t>::max() - value.size() - 4) reject();
        size += value.size() + 4;
    }
    result.reserve(size);
    for (const auto& value : values) {
        if (value.size() > std::numeric_limits<std::uint32_t>::max()) reject();
        for (int shift = 24; shift >= 0; shift -= 8) result.push_back(static_cast<std::uint8_t>(value.size() >> shift));
        record::append(result, value);
    }
    return result;
}
inline Bytes joined(const Bytes& a, const Bytes& b) {
    if (b.size() > std::numeric_limits<std::size_t>::max() - a.size()) reject();
    Bytes result; result.reserve(a.size()+b.size()); record::append(result,a); record::append(result,b); return result;
}
inline Bytes hash(const Bytes& value) { return record::sha256(value); }
inline bool equal(const Bytes& a, const Bytes& b) {
    return a.size() == b.size() && CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}
inline void wipe(Bytes& value) {
    if (!value.empty()) OPENSSL_cleanse(value.data(), value.size());
    value.clear();
}
inline void wipe(Secret& value) { value.clear(); }
inline std::string hex_view(std::span<const unsigned char> value) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string result(value.size()*2,'\0');
    for (std::size_t n=0;n<value.size();++n) {
        const auto ch=value[n]; result[n*2]=digits[ch>>4];result[n*2+1]=digits[ch&15];
    }
    return result;
}
inline std::string hex(const Bytes& value) { return hex_view(value); }
inline Bytes unhex(std::string_view value, std::size_t maximum, std::size_t exact = 0) {
    if (value.size() % 2 || value.size() / 2 > maximum || (exact && value.size() != exact * 2)) reject();
    const auto digit = [](char ch) -> unsigned {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        reject();
    };
    Bytes result(value.size()/2);
    for (std::size_t i = 0; i < value.size(); i += 2) result[i/2]=digit(value[i])*16+digit(value[i+1]);
    return result;
}
#ifdef CR01_CHANNEL_TESTING
// Compile-time-only return-failure injection. No runtime seed/provider override.
enum class BackendFailure { None, Nonce, KeyGeneration, Encapsulation, Signature };
inline BackendFailure backend_failure = BackendFailure::None;
#endif
inline int backend_random(unsigned char* output, int size) {
#ifdef CR01_CHANNEL_TESTING
    if (backend_failure == BackendFailure::Nonce) {
        std::fill_n(output, size, 0xa5); return 0;
    }
#endif
    return RAND_bytes(output, size);
}
inline int backend_generate(EVP_PKEY_CTX* context, EVP_PKEY** key) {
    const int result = EVP_PKEY_generate(context, key);
#ifdef CR01_CHANNEL_TESTING
    if (backend_failure == BackendFailure::KeyGeneration) return 0; // Exercise partial-key cleanup too.
#endif
    return result;
}
inline int backend_sign(EVP_MD_CTX* context, unsigned char* output, std::size_t* size,
                        const unsigned char* message, std::size_t length) {
#ifdef CR01_CHANNEL_TESTING
    if (backend_failure == BackendFailure::Signature) return 0;
#endif
    return EVP_DigestSign(context, output, size, message, length);
}
inline int backend_encapsulate(EVP_PKEY_CTX* context, unsigned char* ciphertext, std::size_t* ct_size,
                               unsigned char* secret, std::size_t* secret_size) {
#ifdef CR01_CHANNEL_TESTING
    if (backend_failure == BackendFailure::Encapsulation) {
        std::fill_n(secret, *secret_size, 0xa5); return 0;
    }
#endif
    return EVP_PKEY_encapsulate(context, ciphertext, ct_size, secret, secret_size);
}
inline Bytes random_bytes(std::size_t size) {
    if (size > 65536) reject();
    Bytes result(size);
    if (backend_random(result.data(), static_cast<int>(size)) != 1) { wipe(result); reject(); }
    return result;
}
inline Key generate(const char* algorithm) {
    KeyContext ctx(EVP_PKEY_CTX_new_from_name(nullptr, algorithm, nullptr), EVP_PKEY_CTX_free);
    EVP_PKEY* key = nullptr;
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0) reject();
    const int status = backend_generate(ctx.get(), &key);
    Key owned(key, EVP_PKEY_free);
    if (status <= 0 || !owned) reject();
    return owned;
}
inline Bytes public_bytes(EVP_PKEY* key, std::size_t expected) {
    Bytes result(expected);
    auto size = result.size();
    if (EVP_PKEY_get_raw_public_key(key, result.data(), &size) <= 0 || size != expected) reject();
    return result;
}
inline Key public_key(const Bytes& value, const char* algorithm, std::size_t expected) {
    if (value.size() != expected) reject();
    Key key(EVP_PKEY_new_raw_public_key_ex(nullptr, algorithm, nullptr, value.data(), value.size()), EVP_PKEY_free);
    if (!key) reject();
    return key;
}
inline Bytes sign(EVP_PKEY* key, const Bytes& message) {
    DigestContext ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    Bytes signature(3309);
    auto size = signature.size();
    if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key) <= 0
        || backend_sign(ctx.get(), signature.data(), &size, message.data(), message.size()) <= 0 || size != 3309) reject();
    return signature;
}
inline void verify(EVP_PKEY* key, const Bytes& message, const Bytes& signature) {
    if (signature.size() != 3309) reject();
    DigestContext ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key) <= 0
        || EVP_DigestVerify(ctx.get(), signature.data(), signature.size(), message.data(), message.size()) != 1) reject();
}
inline std::pair<Secret, Bytes> encapsulate(EVP_PKEY* key) {
    KeyContext ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr), EVP_PKEY_CTX_free);
    Bytes ciphertext(1088);
    Secret secret(32);
    auto ct_size = ciphertext.size(), secret_size = secret.size();
    if (!ctx || EVP_PKEY_encapsulate_init(ctx.get(), nullptr) <= 0
        || backend_encapsulate(ctx.get(), ciphertext.data(), &ct_size, secret.data(), &secret_size) <= 0
        || ct_size != 1088 || secret_size != 32) reject();
    // Move protected storage without copying the secret into an ordinary vector.
    return {std::move(secret), std::move(ciphertext)};
}
inline Secret decapsulate(EVP_PKEY* key, const Bytes& ciphertext) {
    if (ciphertext.size() != 1088) reject();
    KeyContext ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, key, nullptr), EVP_PKEY_CTX_free);
    Secret secret(32);
    auto size = secret.size();
    if (!ctx || EVP_PKEY_decapsulate_init(ctx.get(), nullptr) <= 0
        || EVP_PKEY_decapsulate(ctx.get(), secret.data(), &size, ciphertext.data(), ciphertext.size()) <= 0 || size != 32) {
        wipe(secret); reject();
    }
    return secret;
}
inline void secret_hmac_into(std::span<const unsigned char> key, std::span<const unsigned char> data,
                             std::span<unsigned char> output) {
    if (key.size() > record::kMaxPayloadBytes || output.size() != 32) reject();
    unsigned length = 0;
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(), output.data(), &length)
        || length != output.size()) reject();
}
inline Secret secret_hmac(std::span<const unsigned char> key, std::span<const unsigned char> data) {
    Secret output(32);
    secret_hmac_into(key, data, {output.data(), output.size()});
    return output;
}
inline void expand_label_into(std::span<const unsigned char> prk, const std::string& label,
                              std::span<unsigned char> output) {
    Bytes info = joined(domain(), bytes(label));
    info.push_back(1);
    secret_hmac_into(prk, info, output);
}
inline Secret expand_label(const Secret& prk, const std::string& label) {
    Secret output(32);
    expand_label_into(prk.view(), label, {output.data(), output.size()});
    return output;
}
inline Secret derive(const Secret& secret, const Bytes& transcript, const std::string& label) {
    Secret prk=secret_hmac(transcript,secret.view());
    return expand_label(prk,label);
}
inline Bytes hash_flights(std::initializer_list<std::span<const unsigned char>> values) {
    DigestContext ctx(EVP_MD_CTX_new(),EVP_MD_CTX_free);
    if(!ctx || EVP_DigestInit_ex(ctx.get(),EVP_sha256(),nullptr)!=1
        || EVP_DigestUpdate(ctx.get(),domain().data(),domain().size())!=1)reject();
    for(auto value:values) {
        if(value.size()>std::numeric_limits<std::uint32_t>::max())reject();
        std::array<unsigned char,4> length{};
        for(unsigned n=0;n<4;++n)length[n]=static_cast<unsigned char>(value.size()>>(24-8*n));
        if(EVP_DigestUpdate(ctx.get(),length.data(),length.size())!=1
            || (!value.empty() && EVP_DigestUpdate(ctx.get(),value.data(),value.size())!=1))reject();
    }
    Bytes result(32);unsigned length=0;
    if(EVP_DigestFinal_ex(ctx.get(),result.data(),&length)!=1||length!=32)reject();
    return result;
}

inline Bytes read_regular(const std::filesystem::path& path, std::size_t maximum) {
    // Generic bounded data IO, also used by diagnostic baselines; not trust admission.
    return identity::read<Bytes>(path, maximum, false, false);
}
inline Bytes read_peer_pin(const std::filesystem::path& path) {
    return identity::read<Bytes>(path, 4096, false);
}
inline int no_password(char*, int, int, void*) { return 0; }
inline Key load_identity(const std::filesystem::path& path) {
    Secret encoded = identity::read_private(path);
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(encoded.data(), static_cast<int>(encoded.size())), BIO_free);
    Key key(bio ? PEM_read_bio_PrivateKey(bio.get(), nullptr, no_password, nullptr) : nullptr, EVP_PKEY_free);
    if (!key || EVP_PKEY_is_a(key.get(), "ML-DSA-65") != 1) reject();
    char trailing;
    while (BIO_read(bio.get(), &trailing, 1) == 1)
        if (trailing != ' ' && trailing != '\r' && trailing != '\n' && trailing != '\t') reject();
    return key;
}
inline Bytes generate_identity_file(const std::filesystem::path& path) {
    Key key = generate("ML-DSA-65");
    auto file = identity::create(path);
    bool okay = false;
    {
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_fp(file.get(), BIO_NOCLOSE), BIO_free);
        okay = bio && PEM_write_bio_PrivateKey(bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1;
    }
    const int flushed = fflush(file.get()), closed = fclose(file.release());
    if (!okay || flushed != 0 || closed != 0) reject();
    return public_bytes(key.get(), 1952);
}
inline void write_peer_pin(const std::filesystem::path& path, const Bytes& pin) {
    if (pin.size() != 1952) reject();
    auto file = identity::create(path); // Public bytes, restrictive write/control access.
    const auto count = fwrite(pin.data(), 1, pin.size(), file.get());
    const int flushed = fflush(file.get()), closed = fclose(file.release());
    if (count != pin.size() || flushed != 0 || closed != 0) reject();
}
} // namespace cr01::channel
