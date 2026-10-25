#pragma once
// The frozen v2 grammar only: canonical two-field envelope, flat sorted payload,
// unescaped printable ASCII strings and canonical uint64 numbers. Views borrow
// a caller-owned flight for ONE endpoint operation; never retain them in state.
#include "channel_v2_crypto.hpp"
#include <algorithm>
#include <array>
#include <span>
#include <string_view>

namespace cr01::channel {
struct FlightField {
    std::string_view name, value;
    bool number = false;
};
inline void canonical_number(std::string_view value) {
    if (value.empty() || value.size() > 20 || (value.size() > 1 && value[0] == '0')) reject();
    for (char c : value) if (c < '0' || c > '9') reject();
    if (value.size() == 20 && value > std::string_view("18446744073709551615")) reject();
}
inline void canonical_string(std::string_view value) {
    for (unsigned char c : value) if (c < 32 || c > 126 || c == '"' || c == '\\') reject();
}
struct FlightPayload {
    std::array<FlightField, 12> fields{};
    std::size_t count = 0;
    std::string_view encoded, signature;
    const FlightField& field(std::string_view name) const {
        for (std::size_t n = 0; n < count; ++n) if (fields[n].name == name) return fields[n];
        reject();
    }
    std::string_view string(std::string_view name) const {
        const auto& f = field(name); if (f.number) reject(); return f.value;
    }
};
class FlightReader {
    std::string_view input_;
    std::size_t pos_ = 0;
    void literal(std::string_view expected) {
        if (input_.substr(pos_, expected.size()) != expected) reject();
        pos_ += expected.size();
    }
    std::string_view quoted() {
        literal("\""); const auto begin = pos_;
        while (pos_ < input_.size() && input_[pos_] != '"') {
            const auto c = static_cast<unsigned char>(input_[pos_++]);
            if (c < 32 || c > 126 || c == '\\') reject();
        }
        auto value = input_.substr(begin, pos_ - begin); literal("\""); return value;
    }
public:
    explicit FlightReader(const Bytes& frame) {
        if (frame.empty() || frame.size() > 32768) reject();
        input_=std::string_view(reinterpret_cast<const char*>(frame.data()),frame.size());
    }
    FlightPayload parse() {
        FlightPayload result;
        literal("{\"payload\":"); const auto begin = pos_; literal("{");
        if (pos_ < input_.size() && input_[pos_] != '}') for (;;) {
            if (result.count == result.fields.size()) reject();
            auto name = quoted(); literal(":");
            if (result.count && result.fields[result.count-1].name >= name) reject();
            bool number = pos_ < input_.size() && input_[pos_] != '"';
            std::string_view value;
            if (number) {
                const auto start = pos_;
                while (pos_ < input_.size() && input_[pos_] >= '0' && input_[pos_] <= '9') ++pos_;
                value = input_.substr(start, pos_-start); canonical_number(value);
            } else value = quoted();
            result.fields[result.count++] = {name,value,number};
            if (pos_ < input_.size() && input_[pos_] == ',') { ++pos_; continue; }
            break;
        }
        literal("}"); result.encoded = input_.substr(begin,pos_-begin);
        literal(",\"signature\":"); result.signature = quoted(); literal("}");
        if (pos_ != input_.size()) reject();
        return result;
    }
};
inline std::string flight_payload(std::span<const FlightField> fields) {
    std::size_t size = 2;
    std::string_view previous;
    bool first = true;
    for (const auto& f : fields) {
        if (f.name.size()>32768 || f.value.size()>32768) reject();
        canonical_string(f.name);
        if (!first && previous >= f.name) reject();
        if (f.number) canonical_number(f.value); else canonical_string(f.value);
        size += f.name.size()+f.value.size()+3+(f.number?0:2)+(first?0:1);
        if (size > 32768) reject();
        previous = f.name; first = false;
    }
    std::string out; out.reserve(size); out += '{'; first = true;
    for (const auto& f : fields) {
        if (!first) out += ',';
        first = false; out += '"'; out += f.name; out += "\":";
        if (!f.number) out += '"';
        out += f.value;
        if (!f.number) out += '"';
    }
    out += '}'; return out;
}
inline Bytes flight_signature_input(std::string_view payload) {
    if (payload.size() > 32768) reject();
    Bytes out; out.reserve(domain().size()+4+payload.size()); record::append(out,domain());
    for (int shift=24;shift>=0;shift-=8) out.push_back(static_cast<unsigned char>(payload.size() >> shift));
    out.insert(out.end(),payload.begin(),payload.end()); return out;
}
inline Bytes flight_envelope(std::string_view payload, const Bytes& signature) {
    if (signature.size()!=3309) reject();
    std::string out; out.reserve(payload.size()+signature.size()*2+27);
    out += "{\"payload\":"; out += payload; out += ",\"signature\":\""; out += hex(signature); out += "\"}";
    return bytes(out);
}
inline Bytes field_hex(const FlightPayload& payload, std::string_view name, std::size_t size) {
    return unhex(payload.string(name),size,size);
}
} // namespace cr01::channel
