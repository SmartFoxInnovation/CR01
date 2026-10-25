// Test bridge, not a network service. All arguments are public synthetic fixtures.
#include "../../../src/cpp/channel_v2_core.hpp"
#include <iostream>

cr01::record::Bytes unhex(const std::string& value) {
    if (value.size() % 2 || value.size() > 32768) throw std::invalid_argument("fixture hex size");
    cr01::record::Bytes result;
    const auto digit = [](char c) -> unsigned {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        throw std::invalid_argument("fixture hex");
    };
    for (std::size_t i = 0; i < value.size(); i += 2) result.push_back(digit(value[i]) * 16 + digit(value[i+1]));
    return result;
}

int main(int argc, char** argv) {
    try {
        if (argc != 6) throw std::invalid_argument("fixture argument count");
        const auto key = unhex(argv[1]), sid = unhex(argv[2]), frame = unhex(argv[3]);
        const auto plain = unhex(argv[4]), external = unhex(argv[5]);
        if (frame.size() < cr01::v2::kHeader) throw std::invalid_argument("fixture frame");
        const auto direction = frame[4];
        const auto sequence = cr01::v2::get_be(frame, 21, 8);
        if (cr01::v2::open(key, sid, direction, frame) != plain
            || cr01::v2::seal(key, sid, direction, sequence, plain, external) != frame)
            throw std::runtime_error("v2 vector mismatch");
        std::cout << "v2-vector-pass\n";
        return 0;
    } catch (const std::exception&) {
        std::cerr << "v2-vector-rejected\n";
        return 1;
    }
}
