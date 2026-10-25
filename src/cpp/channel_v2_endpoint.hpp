#pragma once
// Full v2 endpoint: private handshake/session ownership, no raw traffic-key API.
#include "channel_v2_crypto.hpp"
#include "channel_v2_core.hpp"
#include "channel_v2_flight.hpp"
#include "json.hpp"
#include <chrono>
#include <functional>
#include <mutex>
#include <set>

namespace cr01::channel {
using Json = fixture::Value;
using Object = std::map<std::string, Json>;
inline Json string_value(const std::string& text) { Json v; v.kind = '"'; v.text = text; return v; }
inline Json number_value(std::uint64_t n) { Json v; v.kind = 'N'; v.text = std::to_string(n); return v; }
inline Json object_value(Object fields) { Json v; v.kind = '{'; v.fields = std::move(fields); return v; }
inline std::string quote(const std::string& value) {
    // Every legitimate v2 string is printable ASCII with no escaping needed.
    for (unsigned char ch : value) if (ch < 32 || ch > 126 || ch == '"' || ch == '\\') reject();
    return "\"" + value + "\"";
}
inline void append_dump(std::string& out, const Json& value, unsigned depth = 0) {
    if (depth > 4) reject();
    if (value.kind == '"') { out += quote(value.text); return; }
    if (value.kind == 'N') { out += std::to_string(fixture::uint64(value.text)); return; }
    if (value.kind != '{') reject();
    out += '{';
    bool first = true;
    for (const auto& [key, child] : value.fields) {
        if (!first) out += ',';
        first = false;
        out += quote(key); out += ':'; append_dump(out, child, depth + 1);
    }
    out += '}';
}
inline std::string dump(const Json& value, unsigned depth = 0) {
    std::string out; out.reserve(256); append_dump(out, value, depth); return out;
}
inline std::string field_string(const Object& fields, const std::string& key) {
    auto item = fields.find(key);
    if (item == fields.end() || item->second.kind != '"') reject();
    return item->second.text;
}
inline Bytes field_hex(const Object& fields, const std::string& key, std::size_t size) {
    return unhex(field_string(fields, key), size, size);
}
inline void exact_fields(const Object& fields, const std::set<std::string>& expected) {
    if (fields.size() != expected.size()) reject();
    for (const auto& name : expected) if (!fields.count(name)) reject();
}

class Endpoint {
    using Clock = std::chrono::steady_clock;
    struct Session {
        Bytes sid;
        v2::RecordCipher send_cipher, receive_cipher;
        unsigned direction;
        std::uint64_t next = 1, highest = 0, seen = 0, received = 0;
        Clock::time_point born = Clock::now(), last = born;
        Session(Bytes id, std::span<const unsigned char> initiator, std::span<const unsigned char> responder, bool is_initiator)
            : sid(std::move(id)), send_cipher(is_initiator ? initiator : responder, true),
              receive_cipher(is_initiator ? responder : initiator, false), direction(is_initiator ? 0 : 1) {}
        Session(const Session&) = delete;
        Session& operator=(const Session&) = delete;
    };
    Key identity_, peer_, ephemeral_{nullptr, EVP_PKEY_free};
    Bytes public_, hello_, reply_, finish_, transcript_;
    Secret secret_;
    Object base_;
    bool initiator_;
    std::string phase_;
    std::uint64_t pid_ = process_id(); // Private and immutable outside test instrumentation.
    Clock::time_point born_ = Clock::now(), last_ = born_;
    std::unique_ptr<Session> session_;
    std::recursive_mutex lock_;
#ifdef CR01_CHANNEL_TESTING
    friend struct EndpointTestAccess;
    bool fail_next_send_ = false; // Fault injection is absent from production.
#endif

    void same_process() const { if (pid_ != process_id()) reject(); }
    void clear_pending() {
        wipe(secret_);
        ephemeral_.reset();
        hello_.clear(); reply_.clear(); finish_.clear(); transcript_.clear();
    }
    void close_unlocked() {
        session_.reset(); identity_.reset(); clear_pending(); phase_ = "closed";
    }
    void check_phase(const std::string& phase) {
        same_process();
        const auto now = Clock::now();
        if (phase_ != phase || now < last_ || now - born_ >= std::chrono::seconds(120)) reject();
        last_ = now;
    }
    template<class F> Bytes transition(const std::string& phase, F operation) {
        same_process(); // Before taking a possibly inherited lock.
        std::lock_guard<std::recursive_mutex> guard(lock_);
        try { check_phase(phase); return operation(); }
        catch (...) { close_unlocked(); throw; }
    }
    void check_session() {
        same_process();
        const auto now = Clock::now();
        if (phase_ != "established" || !session_) reject();
        if (now < session_->last || now - session_->born >= std::chrono::seconds(3600)) {
            close_unlocked(); reject();
        }
        session_->last = now;
    }
    Bytes sign_flight(const std::string& kind, const std::map<std::string, std::string>& extra) {
        std::array<FlightField,12> fields{};
        if (base_.size() > fields.size()-1 || extra.size() > fields.size()-1-base_.size()) reject();
        std::size_t count = 0;
        for (const auto& [key,value] : base_) fields[count++] = {key,value.text,value.kind=='N'};
        fields[count++] = {"kind",kind,false};
        for (const auto& [key,value] : extra) {
            if (count == fields.size()) reject();
            fields[count++] = {key,value,false};
        }
        // At most twelve fields; bounded insertion avoids heap-backed objects.
        for (std::size_t n=1;n<count;++n) {
            auto value=fields[n]; auto pos=n;
            while (pos && fields[pos-1].name>value.name) { fields[pos]=fields[pos-1]; --pos; }
            fields[pos]=value;
        }
        const auto payload = flight_payload({fields.data(),count});
        return flight_envelope(payload,sign(identity_.get(),flight_signature_input(payload)));
    }
    FlightPayload verify_flight(const Bytes& frame, const std::string& kind, std::initializer_list<std::string_view> extra) {
        auto payload = FlightReader(frame).parse();
        if (payload.count != base_.size()+extra.size()+1) reject();
        for (const auto& [key, value] : base_) {
            const auto& found = payload.field(key);
            if (found.number != (value.kind=='N') || found.value != value.text) reject();
        }
        for (const auto& key : extra) payload.string(key);
        if (payload.string("kind") != kind) reject();
        verify(peer_.get(),flight_signature_input(payload.encoded),unhex(payload.signature,3309,3309));
        return payload;
    }
    Bytes transcript(const Bytes& ciphertext) const { return hash_flights({hello_,reply_,ciphertext}); }
    Bytes finished(const std::string& label, const Bytes& input) const {
        // One owned locked mapping, disjoint slots, same extract/expand/MAC bytes.
        // All slots are cleansed together on success and every exceptional exit.
        Secret material(64);
        std::span<unsigned char> prk(material.data(), 32), key(material.data()+32, 32);
        secret_hmac_into(transcript_, secret_.view(), prk);
        expand_label_into(prk, label, key);
        return record::hmac_sha256(key, input);
    }
    Bytes ack() const {
        const auto bound = hash_flights({transcript_,finish_});
        return bytes(dump(object_value({{"version", number_value(2)}, {"kind", string_value("responder_finished")},
            {"transcript", string_value(hex(bound))}, {"finished", string_value(hex(finished("responder-finished", bound)))}})));
    }
    void establish(const Bytes& confirmed) {
        const auto final = hash_flights({transcript_,finish_,confirmed});
        Bytes id(final.begin(), final.begin() + 16);
        Secret material(96);
        std::span<unsigned char> prk(material.data(),32), ikey(material.data()+32,32), rkey(material.data()+64,32);
        secret_hmac_into(final,secret_.view(),prk);
        expand_label_into(prk,"initiator-traffic",ikey);
        expand_label_into(prk,"responder-traffic",rkey);
        // Guards retain key buffers until both EVP contexts are constructed,
        // including allocation/setup failures. Only keyed provider state persists.
        session_ = std::make_unique<Session>(std::move(id), ikey, rkey, initiator_);
        clear_pending(); phase_ = "established";
    }
public:
    Endpoint(const std::string& role, Key identity, const Bytes& peer_public, const Bytes& application, std::uint64_t epoch)
        : identity_(std::move(identity)), peer_(nullptr, EVP_PKEY_free), initiator_(role == "initiator") {
        if ((role != "initiator" && role != "responder") || !identity_
            || EVP_PKEY_is_a(identity_.get(), "ML-DSA-65") != 1 || peer_public.size() != 1952
            || application.empty() || application.size() > 1024 || epoch == 0) reject();
        public_ = public_bytes(identity_.get(), 1952);
        if (equal(public_, peer_public)) reject();
        peer_ = public_key(peer_public, "ML-DSA-65", 1952);
        const auto own = hex(hash(public_)), peer = hex(hash(peer_public));
        base_ = {{"version", number_value(2)}, {"suite", string_value("ML-KEM-768/ML-DSA-65/HKDF-SHA256/AES-256-GCM")},
            {"application", string_value(hex(application))}, {"epoch", number_value(epoch)},
            {"initiator", string_value(initiator_ ? own : peer)}, {"responder", string_value(initiator_ ? peer : own)}};
        phase_ = initiator_ ? "new_i" : "new_r";
    }
    ~Endpoint() { close_unlocked(); }
    Endpoint(const Endpoint&) = delete;
    Endpoint(Endpoint&&) = delete;
    Endpoint& operator=(const Endpoint&) = delete;
    Endpoint& operator=(Endpoint&&) = delete;
    Bytes public_identity() const { return public_; }
    std::string phase() { same_process(); std::lock_guard<std::recursive_mutex> guard(lock_); return phase_; }
    Bytes session_id() {
        same_process(); std::lock_guard<std::recursive_mutex> guard(lock_); check_session(); return session_->sid;
    }
    void close() { same_process(); std::lock_guard<std::recursive_mutex> guard(lock_); close_unlocked(); }
    Bytes start() {
        return transition("new_i", [&] {
            hello_ = sign_flight("initiator_hello", {{"nonce", hex(random_bytes(32))}});
            phase_ = "await_reply"; return hello_;
        });
    }
    Bytes respond(const Bytes& hello) {
        return transition("new_r", [&] {
            const auto payload = verify_flight(hello, "initiator_hello", {"nonce"});
            field_hex(payload, "nonce", 32);
            hello_ = hello;
            ephemeral_ = generate("ML-KEM-768");
            reply_ = sign_flight("responder_hello", {{"hello_hash", hex(hash(hello))},
                {"nonce", hex(random_bytes(32))}, {"kem_public", hex(public_bytes(ephemeral_.get(), 1184))}});
            phase_ = "await_finish"; return reply_;
        });
    }
    Bytes finish(const Bytes& reply) {
        return transition("await_reply", [&] {
            const auto payload = verify_flight(reply, "responder_hello", {"hello_hash", "nonce", "kem_public"});
            if (!equal(field_hex(payload, "hello_hash", 32), hash(hello_))) reject();
            field_hex(payload, "nonce", 32);
            auto public_kem = public_key(field_hex(payload, "kem_public", 1184), "ML-KEM-768", 1184);
            auto [secret, ciphertext] = encapsulate(public_kem.get());
            secret_ = std::move(secret); reply_ = reply; transcript_ = transcript(ciphertext);
            finish_ = sign_flight("initiator_finish", {{"hello_hash", hex(hash(hello_))}, {"reply_hash", hex(hash(reply))},
                {"kem_ciphertext", hex(ciphertext)}, {"finished", hex(finished("initiator-finished", transcript_))}});
            phase_ = "await_confirm"; return finish_;
        });
    }
    Bytes accept(const Bytes& finish) {
        return transition("await_finish", [&] {
            const auto payload = verify_flight(finish, "initiator_finish", {"hello_hash", "reply_hash", "kem_ciphertext", "finished"});
            if (!equal(field_hex(payload, "hello_hash", 32), hash(hello_))
                || !equal(field_hex(payload, "reply_hash", 32), hash(reply_))) reject();
            const auto ciphertext = field_hex(payload, "kem_ciphertext", 1088);
            secret_ = decapsulate(ephemeral_.get(), ciphertext); transcript_ = transcript(ciphertext);
            if (!equal(field_hex(payload, "finished", 32), finished("initiator-finished", transcript_))) reject();
            finish_ = finish;
            auto confirmation = ack(); establish(confirmation); return confirmation;
        });
    }
    Bytes confirm(const Bytes& confirmation) {
        return transition("await_confirm", [&] {
            if (confirmation.size() > 32768 || !equal(confirmation, ack())) reject();
            establish(confirmation); return Bytes{};
        });
    }
    Bytes send(const Bytes& plaintext, const Bytes& external) {
        Bytes output;
        send_into(plaintext, external, output);
        return output;
    }
    void send_into(const Bytes& plaintext, const Bytes& external, Bytes& output) {
        if (&output == &plaintext || &output == &external) reject();
        same_process(); std::lock_guard<std::recursive_mutex> guard(lock_); check_session();
        if (plaintext.size() > record::kMaxPayloadBytes || external.size() > record::kMaxAadBytes) reject();
        if (session_->next > v2::kMaxMessages) { close_unlocked(); reject(); }
        const auto sequence = session_->next++; // Reserve even if EVP later fails.
#ifdef CR01_CHANNEL_TESTING
        if (fail_next_send_) { fail_next_send_ = false; reject(); }
#endif
        v2::seal_into(session_->send_cipher, session_->sid, session_->direction, sequence, plaintext, external, output);
    }
private:
    template<class Frame,class Open> auto receive_checked(Frame& frame, const Bytes* expected_aad, Open open) {
        same_process(); std::lock_guard<std::recursive_mutex> guard(lock_); check_session();
        if (frame.size() < v2::kHeader + 16 || frame.size() > v2::kHeader + record::kMaxAadBytes + record::kMaxPayloadBytes + 16
            || (expected_aad && expected_aad->size() > record::kMaxAadBytes) || session_->received >= v2::kMaxMessages) reject();
        const auto sequence = v2::get_be(frame, 21, 8), external_size = v2::get_be(frame, 29, 4);
        if (!sequence || sequence > v2::kMaxMessages || external_size > record::kMaxAadBytes || frame.size() < v2::kHeader + external_size + 16) reject();
        if (expected_aad && (expected_aad->size() != external_size
            || !std::equal(expected_aad->begin(), expected_aad->end(), frame.begin() + v2::kHeader))) reject();
        if (sequence <= session_->highest) {
            const auto distance = session_->highest - sequence;
            if (distance >= 64 || (session_->seen & (std::uint64_t{1} << distance))) reject();
        }
        auto plaintext = open(session_->receive_cipher, session_->sid, 1 - session_->direction, frame);
        if (sequence > session_->highest) {
            const auto shift = sequence - session_->highest;
            session_->seen = shift >= 64 ? 0 : session_->seen << shift;
            session_->highest = sequence;
        }
        session_->seen |= std::uint64_t{1} << (session_->highest - sequence);
        ++session_->received;
        return plaintext;
    }
public:
    Bytes receive(const Bytes& frame, const Bytes* expected_aad = nullptr) {
        // Compatibility allocation/copy completes BEFORE replay commit too.
        return receive_checked(frame,expected_aad,[](auto& cipher,const auto& sid,unsigned direction,const auto& input) {
            return v2::open(cipher,sid,direction,input);
        });
    }
    v2::AuthenticatedRecord receive_owned(Bytes frame, const Bytes* expected_aad = nullptr) {
        return receive_checked(frame,expected_aad,[](auto& cipher,const auto& sid,unsigned direction,auto& input) {
            return v2::open_owned(cipher,sid,direction,std::move(input));
        });
    }
};
} // namespace cr01::channel
