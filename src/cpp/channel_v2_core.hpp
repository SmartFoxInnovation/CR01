#pragma once
// Stateless v2 record adapter only. Host owns handshake, counters and replay policy.
#include "crypto.hpp"
#include "channel_v2_gcm.hpp"
#include "channel_v2_plaintext.hpp"
#include <algorithm>

namespace cr01::v2 {
using record::Bytes;
constexpr std::size_t kHeader = 37;
constexpr std::uint64_t kMaxMessages = 1000000;

inline void put32(Bytes& out, std::size_t n) {
    for (int shift = 24; shift >= 0; shift -= 8) out.push_back(static_cast<std::uint8_t>(n >> shift));
}

inline std::uint64_t get_be(const Bytes& data, std::size_t offset, std::size_t count) {
    std::uint64_t n = 0;
    for (std::size_t index = 0; index < count; ++index) n = (n << 8) | data.at(offset + index);
    return n;
}

inline Bytes nonce(std::uint64_t sequence) {
    Bytes result(4, 0);
    record::append(result, record::uint64_be(sequence));
    return result;
}

inline Bytes aad(const Bytes& header, const Bytes& external) {
    Bytes result = record::ascii_bytes("CR01-SC-CHANNEL-v2");
    result.reserve(result.size() + 1 + header.size() + external.size());
    result.push_back(0);
    record::append(result, header);
    record::append(result, external);
    return result;
}

// Caller-owned ciphertext storage only; no session/traffic state is cached here.
// The output is valid only on success. Never alias input, AAD or session id.
inline void seal_into(RecordCipher& cipher, const Bytes& sid, unsigned direction, std::uint64_t sequence,
                      const Bytes& plaintext, const Bytes& external, Bytes& output) {
    if (&output == &plaintext || &output == &external || &output == &sid)
        throw std::invalid_argument("v2 output aliases input");
    struct ClearOnFailure {
        Bytes& value; bool complete = false;
        ~ClearOnFailure() { if (!complete) { if (!value.empty()) OPENSSL_cleanse(value.data(), value.size()); value.clear(); } }
    } guard{output};
    if (sid.size() != 16 || direction > 1 || sequence == 0 || sequence > kMaxMessages
        || plaintext.size() > record::kMaxPayloadBytes || external.size() > record::kMaxAadBytes || !cipher.is_encrypting())
        throw std::invalid_argument("v2 record rejected");
    Bytes header = record::ascii_bytes("CR02");
    header.reserve(kHeader + external.size());
    header.push_back(static_cast<std::uint8_t>(direction));
    record::append(header, sid);
    record::append(header, record::uint64_be(sequence));
    put32(header, external.size());
    put32(header, plaintext.size() + 16);
    record::append(header, external);
    const auto offset = header.size();
    // resize does not initialize an already-sized payload again. First use and
    // growth still initialize normally; no writes into unconstructed capacity.
    output.resize(offset + plaintext.size() + 16);
    std::copy(header.begin(), header.end(), output.begin());
    const auto iv = nonce(sequence);
    cipher.apply(std::span<const unsigned char,12>(iv.data(),12), {header.data(),kHeader}, external, plaintext,
        {output.data()+offset,plaintext.size()+16}, std::span<unsigned char,16>(output.data()+offset+plaintext.size(),16));
    guard.complete = true;
}

inline Bytes seal(RecordCipher& cipher, const Bytes& sid, unsigned direction, std::uint64_t sequence,
                  const Bytes& plaintext, const Bytes& external) {
    Bytes output;
    seal_into(cipher, sid, direction, sequence, plaintext, external, output);
    return output;
}

struct RecordLayout { std::uint64_t sequence; std::size_t external, plaintext; };
inline RecordLayout validate_record(RecordCipher& cipher, const Bytes& sid, unsigned expected_direction, const Bytes& frame) {
    if (sid.size() != 16 || expected_direction > 1 || frame.size() < kHeader + 16
        || frame.size() > kHeader + record::kMaxAadBytes + record::kMaxPayloadBytes + 16 || cipher.is_encrypting())
        throw std::invalid_argument("v2 record rejected");
    const auto sequence = get_be(frame, 21, 8);
    const auto external_size = get_be(frame, 29, 4), sealed_size = get_be(frame, 33, 4);
    if (frame[0] != 'C' || frame[1] != 'R' || frame[2] != '0' || frame[3] != '2'
        || frame[4] != expected_direction || !std::equal(sid.begin(), sid.end(), frame.begin()+5)
        || sequence == 0 || sequence > kMaxMessages || external_size > record::kMaxAadBytes
        || sealed_size < 16 || sealed_size > record::kMaxPayloadBytes + 16
        || frame.size() != kHeader + external_size + sealed_size)
        throw std::invalid_argument("v2 record rejected");
    return {sequence,static_cast<std::size_t>(external_size),static_cast<std::size_t>(sealed_size-16)};
}
inline void authenticate_record(RecordCipher& cipher,const Bytes& frame,RecordLayout layout,std::span<unsigned char> output) {
    std::array<unsigned char,16> tag{};
    std::copy(frame.end()-16, frame.end(), tag.begin());
    const auto iv = nonce(layout.sequence);
    cipher.apply(std::span<const unsigned char,12>(iv.data(),12), {frame.data(),kHeader},
        {frame.data()+kHeader,layout.external}, {frame.data()+kHeader+layout.external,layout.plaintext},output,tag);
}
inline AuthenticatedRecord open_owned(RecordCipher& cipher, const Bytes& sid, unsigned expected_direction, Bytes frame) {
    const auto layout = validate_record(cipher,sid,expected_direction,frame);
    AuthenticatedRecord plaintext(std::move(frame),kHeader+layout.external,layout.plaintext);
    // Tag is copied before EVP writes. Exact in-place payload spans; the
    // existing 16 tag bytes leave room for the provider's final-output bound.
    authenticate_record(cipher,plaintext.storage_,layout,
        {plaintext.storage_.data()+plaintext.offset_,layout.plaintext+1});
    // apply verified the tag AND exact written length. Only now can ownership
    // leave this scope. The deleter wipes on all failures and on success release.
    return plaintext;
}

inline Bytes open(RecordCipher& cipher, const Bytes& sid, unsigned expected_direction, const Bytes& frame) {
    const auto layout = validate_record(cipher,sid,expected_direction,frame);
    const auto size = layout.plaintext;
    Bytes plaintext(size + 1);
    record::WipeOnExit failure_guard(plaintext);
    authenticate_record(cipher,frame,layout,plaintext);
    plaintext.resize(size);
    Bytes authenticated = std::move(plaintext);
    return authenticated;
}

// Compatibility stateless adapter: caller still supplies the key; no replay or
// nonce ownership is implied. Full endpoints use the typed session-owned path.
inline Bytes seal(const Bytes& key, const Bytes& sid, unsigned direction, std::uint64_t sequence,
                  const Bytes& plaintext, const Bytes& external) {
    RecordCipher cipher(key,true); return seal(cipher,sid,direction,sequence,plaintext,external);
}
inline Bytes open(const Bytes& key, const Bytes& sid, unsigned expected_direction, const Bytes& frame) {
    RecordCipher cipher(key,false); return open(cipher,sid,expected_direction,frame);
}
} // namespace cr01::v2
