#pragma once
// CRB1 is bounded local control framing, not a new encrypted wire protocol.
#include "channel_v2_endpoint.hpp"
#include <array>
#include <iostream>
#include <optional>

namespace cr01::binary {
using channel::Bytes;
constexpr std::size_t kHeader = 16;
constexpr std::size_t kMaxFrame = v2::kHeader + record::kMaxAadBytes + record::kMaxPayloadBytes + 16;
enum Operation : unsigned char { Ready = 0, Start = 1, Respond = 2, Finish = 3, Accept = 4,
    Confirm = 5, Send = 6, Receive = 7, Status = 8, Close = 9, Rejected = 255 };
enum Result : unsigned char { Okay = 0, Reject = 1, EndpointReady = 2 };

inline unsigned char phase_code(const std::string& phase) {
    if (phase == "new_i") return 1;
    if (phase == "new_r") return 2;
    if (phase == "await_reply") return 3;
    if (phase == "await_finish") return 4;
    if (phase == "await_confirm") return 5;
    if (phase == "established") return 6;
    if (phase == "closed") return 7;
    channel::reject();
}
inline std::uint32_t length(const std::array<unsigned char, kHeader>& header, std::size_t offset) {
    std::uint32_t value = 0;
    for (unsigned n = 0; n < 4; ++n) value = (value << 8) | header[offset + n];
    return value;
}
inline void put_length(std::array<unsigned char, kHeader>& header, std::size_t offset, std::size_t value) {
    if (value > kMaxFrame) channel::reject();
    for (unsigned n = 0; n < 4; ++n) header[offset + n] = static_cast<unsigned char>(value >> (24 - 8*n));
}
inline void emit(unsigned char op, unsigned char status, unsigned char phase,
                 std::span<const unsigned char> data = {}, std::span<const unsigned char> auxiliary = {}) {
    std::array<unsigned char, kHeader> header{'C','R','B','1',op,status,phase,0};
    put_length(header, 8, data.size()); put_length(header, 12, auxiliary.size());
    if (op>=Start && op<=Confirm && data.size()<=32768 && auxiliary.size()<=16) {
        // One bounded write avoids waking the peer on a header whose body is
        // not yet in the pipe. Bytes and explicit flush behaviour are identical.
        Bytes packet;packet.reserve(header.size()+data.size()+auxiliary.size());
        packet.insert(packet.end(),header.begin(),header.end());
        packet.insert(packet.end(),data.begin(),data.end());packet.insert(packet.end(),auxiliary.begin(),auxiliary.end());
        std::cout.write(reinterpret_cast<const char*>(packet.data()),packet.size());
    } else {
        std::cout.write(reinterpret_cast<const char*>(header.data()), header.size());
        if (!data.empty()) std::cout.write(reinterpret_cast<const char*>(data.data()), data.size());
        if (!auxiliary.empty()) std::cout.write(reinterpret_cast<const char*>(auxiliary.data()), auxiliary.size());
    }
    std::cout.flush();
    if (!std::cout) channel::reject();
}
inline void rejected() { emit(Rejected, Reject, 0); }
inline void emit_received(unsigned char phase,v2::AuthenticatedRecord plaintext,const Bytes& sid,Bytes& recycled) {
    if(sid.size()!=16) channel::reject();
    std::array<unsigned char,kHeader> header{'C','R','B','1',Receive,Okay,phase,0};
    const auto view=plaintext.view();put_length(header,8,view.size());put_length(header,12,sid.size());
    std::cout.write(reinterpret_cast<const char*>(header.data()),header.size());
    if(!view.empty()) std::cout.write(reinterpret_cast<const char*>(view.data()),view.size());
    // Finish cleansing BEFORE the final response bytes, not outside app timing.
    recycled=plaintext.take_cleansed_storage();
    std::cout.write(reinterpret_cast<const char*>(sid.data()),sid.size());std::cout.flush();
    if(!std::cout) channel::reject();
}
struct Request { unsigned char operation = 0, flags = 0; Bytes data, auxiliary; };

inline bool read_request(Request& request) {
    std::array<unsigned char, kHeader> header{};
    std::cin.read(reinterpret_cast<char*>(header.data()), header.size());
    if (std::cin.gcount() == 0 && std::cin.eof()) return false;
    if (std::cin.gcount() != static_cast<std::streamsize>(header.size())) channel::reject();
    if (header[0] != 'C' || header[1] != 'R' || header[2] != 'B' || header[3] != '1'
        || header[6] || header[7]) channel::reject();
    const auto op = header[4], flags = header[5];
    const auto data_size = length(header, 8), auxiliary_size = length(header, 12);
    // Check the operation's limits BEFORE allocation or reading its body.
    if (flags && !(op == Receive && flags == 1)) channel::reject();
    switch (op) {
        case Start: case Status: case Close:
            if (data_size || auxiliary_size) channel::reject();
            break;
        case Respond: case Finish: case Accept: case Confirm:
            if (data_size > 32768 || auxiliary_size) channel::reject();
            break;
        case Send:
            if (data_size > record::kMaxPayloadBytes || auxiliary_size > record::kMaxAadBytes) channel::reject();
            break;
        case Receive:
            if (data_size > kMaxFrame || auxiliary_size > record::kMaxAadBytes
                || (!flags && auxiliary_size)) channel::reject();
            break;
        default: channel::reject();
    }
    request.operation = op; request.flags = flags;
    request.data.resize(data_size); request.auxiliary.resize(auxiliary_size);
    for (auto* part : {&request.data, &request.auxiliary}) {
        if (part->empty()) continue;
        std::cin.read(reinterpret_cast<char*>(part->data()), part->size());
        if (std::cin.gcount() != static_cast<std::streamsize>(part->size())) channel::reject();
    }
    return true;
}
inline void run(channel::Endpoint& endpoint) {
    emit(Ready, EndpointReady, phase_code(endpoint.phase()), endpoint.public_identity(),
         channel::bytes(OpenSSL_version(OPENSSL_VERSION)));
    Request request;
    Bytes send_output;
    record::WipeOnExit output_guard(send_output);
    while (read_request(request)) {
        try {
            Bytes data;
            std::optional<v2::AuthenticatedRecord> received;
            switch (request.operation) {
                case Start: data = endpoint.start(); break;
                case Respond: data = endpoint.respond(request.data); break;
                case Finish: data = endpoint.finish(request.data); break;
                case Accept: data = endpoint.accept(request.data); break;
                case Confirm: data = endpoint.confirm(request.data); break;
                case Send: endpoint.send_into(request.data, request.auxiliary, send_output); break;
                case Receive:
                    received = endpoint.receive_owned(std::move(request.data), request.flags ? &request.auxiliary : nullptr); break;
                case Status: break;
                case Close: endpoint.close(); break;
                default: channel::reject();
            }
            const auto phase = endpoint.phase();
            if(received) emit_received(phase_code(phase),std::move(*received),endpoint.session_id(),request.data);
            else emit(request.operation, Okay, phase_code(phase), request.operation == Send ? send_output : data,
                      phase == "established" ? endpoint.session_id() : Bytes{});
        } catch (const std::exception&) { rejected(); }
    }
    endpoint.close();
}
} // namespace cr01::binary
