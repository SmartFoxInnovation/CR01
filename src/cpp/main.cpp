// Full v2 endpoint: JSON-lines (default) or opt-in CRB1 binary local control.
#include "channel_v2_endpoint.hpp"
#include "channel_binary.hpp"
#include <iostream>

namespace {
using namespace cr01::channel;
constexpr std::size_t kMaxControlLine = 2 * (cr01::record::kMaxPayloadBytes + cr01::record::kMaxAadBytes + 128) + 128;
void emit(const Object& response) { std::cout << dump(object_value(response)) << '\n' << std::flush; }
bool read_line(std::string& line) {
    line.clear();
    char ch;
    while (std::cin.get(ch)) {
        if (ch == '\n') return true;
        if (line.size() >= kMaxControlLine) reject();
        line += ch;
    }
    if (!line.empty()) reject(); // A truncated command is not executed at EOF.
    return false;
}
}

int main(int argc, char** argv) {
    bool binary_mode = false;
    for (int i = 1; i + 1 < argc; i += 2)
        if (std::string(argv[i]) == "--transport" && std::string(argv[i+1]) == "binary") binary_mode = true;
    try {
        cr01::memory::restrict_process_dumps();
        // Every response explicitly flushes; never flush tied stdout once per
        // input character in JSON mode. Binary translation still opts in below.
        std::ios::sync_with_stdio(false);
        std::cin.tie(nullptr);
        if (binary_mode) {
#ifdef _WIN32
            if (_setmode(_fileno(stdin), _O_BINARY) == -1 || _setmode(_fileno(stdout), _O_BINARY) == -1) reject();
#endif
        }
        if (argc == 2 && std::string(argv[1]) == "--help") {
            emit({{"usage", string_value("cr01sc --memory-status | --generate-identity FILE | --write-peer-pin FILE HEX | --role initiator|responder --identity FILE --peer-public FILE --application HEX --epoch UINT [--transport json|binary]")}});
            return 0;
        }
        if (argc == 2 && std::string(argv[1]) == "--memory-status") {
            cr01::memory::Secret probe(32); // Fail, never claim success after a fallback.
            emit({{"status", string_value("locked-buffer-probe-passed")},
                  {"scope", string_value("application-owned native secrets only")},
#ifdef _WIN32
                  {"dump_policy", string_value("Windows host policy required")},
#else
                  {"dump_policy", string_value("Linux DONTDUMP pages and process dump restrictions")},
#endif
                  {"provider_memory", string_value("not covered")},
                  {"rollback_detection", string_value("not provided")}});
            return 0;
        }
        if (argc == 3 && std::string(argv[1]) == "--generate-identity") {
            auto public_value = generate_identity_file(std::filesystem::path(argv[2]));
            emit({{"status", string_value("identity-created")}, {"public_key", string_value(hex(public_value))}});
            return 0;
        }
        if (argc == 4 && std::string(argv[1]) == "--write-peer-pin") {
            write_peer_pin(std::filesystem::path(argv[2]), unhex(argv[3],1952,1952));
            emit({{"status", string_value("pin-written")}});
            return 0;
        }
        std::map<std::string, std::string> options;
        for (int i = 1; i < argc; i += 2) {
            if (i + 1 >= argc || !options.emplace(argv[i], argv[i+1]).second) reject();
        }
        if (options.count("--transport")) {
            const auto transport = options.at("--transport");
            if (transport != "json" && transport != "binary") reject();
            options.erase("--transport");
        }
        if (options.size() != 5) reject();
        for (const auto* name : {"--role", "--identity", "--peer-public", "--application", "--epoch"}) if (!options.count(name)) reject();
        Bytes pin = read_peer_pin(std::filesystem::path(options.at("--peer-public")));
        if (pin.size() != 1952) {
            auto encoded = text(pin);
            if (!encoded.empty() && encoded.back() == '\n') encoded.pop_back();
            if (!encoded.empty() && encoded.back() == '\r') encoded.pop_back();
            pin = unhex(encoded, 1952, 1952);
        }
        Endpoint endpoint(options.at("--role"), load_identity(std::filesystem::path(options.at("--identity"))), pin,
                          unhex(options.at("--application"), 1024), cr01::fixture::uint64(options.at("--epoch")));
        if (binary_mode) { cr01::binary::run(endpoint); return 0; }
        emit({{"status", string_value("endpoint-ready")}, {"version", number_value(2)},
              {"public_key", string_value(hex(endpoint.public_identity()))}, {"openssl", string_value(OpenSSL_version(OPENSSL_VERSION))}});
        std::string line;
        Bytes send_output;
        cr01::record::WipeOnExit output_guard(send_output);
        while (read_line(line)) {
            try {
                const auto request = cr01::fixture::Parser(line, kMaxControlLine).parse();
                const auto op = field_string(request.fields, "op");
                std::set<std::string> fields{"op"};
                if (op == "respond" || op == "finish" || op == "accept" || op == "confirm" || op == "receive") fields.insert("data");
                if (op == "send") { fields.insert("data"); fields.insert("aad"); }
                if (op == "receive" && request.fields.count("expected_aad")) fields.insert("expected_aad");
                exact_fields(request.fields, fields);
                Bytes data;
                std::optional<cr01::v2::AuthenticatedRecord> received;
                if (op == "start") data = endpoint.start();
                else if (op == "respond" || op == "finish" || op == "accept" || op == "confirm") {
                    const auto flight = unhex(field_string(request.fields, "data"), 32768);
                    if (op == "respond") data = endpoint.respond(flight);
                    else if (op == "finish") data = endpoint.finish(flight);
                    else if (op == "accept") data = endpoint.accept(flight);
                    else data = endpoint.confirm(flight);
                } else if (op == "send") {
                    endpoint.send_into(unhex(field_string(request.fields, "data"), cr01::record::kMaxPayloadBytes),
                                       unhex(field_string(request.fields, "aad"), cr01::record::kMaxAadBytes), send_output);
                } else if (op == "receive") {
                    auto frame = unhex(field_string(request.fields, "data"), cr01::v2::kHeader + cr01::record::kMaxAadBytes + cr01::record::kMaxPayloadBytes + 16);
                    if (request.fields.count("expected_aad")) {
                        auto expected = unhex(field_string(request.fields, "expected_aad"), cr01::record::kMaxAadBytes);
                        received = endpoint.receive_owned(std::move(frame), &expected);
                    } else received = endpoint.receive_owned(std::move(frame));
                } else if (op == "close") endpoint.close();
                else if (op != "status") reject();
                const auto output = received ? received->view() : std::span<const unsigned char>(op == "send" ? send_output : data);
                Object response{{"status", string_value("ok")}, {"data", string_value(hex_view(output))}, {"phase", string_value(endpoint.phase())}};
                received.reset(); // Authenticated hex copy exists; wipe raw storage before replying.
                if (endpoint.phase() == "established") response.emplace("session_id", string_value(hex(endpoint.session_id())));
                emit(response);
            } catch (const std::exception&) { emit({{"status", string_value("rejected")}}); }
        }
        endpoint.close();
        return 0;
    } catch (const std::exception&) {
        if (binary_mode) cr01::binary::rejected();
        else emit({{"status", string_value("rejected")}});
        return 1;
    }
}
