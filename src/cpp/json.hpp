#pragma once
// Bounded JSON reader used by canonical local handshake/control frames.
// Keys are restricted to unescaped printable ASCII. Unicode escapes in values
// remain literal and are therefore rejected when a hex/algorithm field is read.
#include <cctype>
#include <cstdint>
#include <map>
#include <stdexcept>
#include <string>

namespace cr01::fixture {
struct Value {
    char kind = 0;
    std::string text;
    std::map<std::string, Value> fields;
};

class Parser {
    const std::string& input;
    std::size_t pos = 0, nodes = 0;
    [[noreturn]] void fail() const { throw std::invalid_argument("invalid or unsupported fixture JSON"); }
    void whitespace() { while (pos < input.size() && (input[pos] == ' ' || input[pos] == '\n' || input[pos] == '\r' || input[pos] == '\t')) ++pos; }
    char take() { if (pos == input.size()) fail(); return input[pos++]; }
    std::string string(bool key = false) {
        if (take() != '"') fail();
        std::string result;
        while (pos < input.size()) {
            char ch = take();
            if (ch == '"') return result;
            if (static_cast<unsigned char>(ch) < 32) fail();
            if (key && (ch == '\\' || static_cast<unsigned char>(ch) > 126)) fail();
            if (ch != '\\') { result += ch; continue; }
            char escape = take();
            switch (escape) {
                case '"': case '\\': case '/': result += escape; break;
                case 'b': result += '\b'; break;
                case 'f': result += '\f'; break;
                case 'n': result += '\n'; break;
                case 'r': result += '\r'; break;
                case 't': result += '\t'; break;
                case 'u':
                    result += "\\u";
                    for (int i = 0; i < 4; ++i) {
                        char digit = take();
                        if (!std::isxdigit(static_cast<unsigned char>(digit))) fail();
                        result += digit;
                    }
                    break;
                default: fail();
            }
        }
        fail();
    }
    Value value(unsigned depth) {
        whitespace();
        if (depth > 32 || ++nodes > 100000 || pos == input.size()) fail();
        const std::size_t start = pos;
        Value out;
        char ch = input[pos];
        out.kind = ch;
        if (ch == '"') { out.text = string(); return out; }
        if (ch == '{' || ch == '[') {
            ++pos;
            whitespace();
            char close = ch == '{' ? '}' : ']';
            if (pos < input.size() && input[pos] == close) { ++pos; out.text = input.substr(start, pos-start); return out; }
            for (;;) {
                whitespace();
                std::string key;
                if (ch == '{') { key = string(true); whitespace(); if (take() != ':') fail(); }
                Value child = value(depth + 1);
                if (ch == '{' && !out.fields.emplace(key, std::move(child)).second) fail();
                whitespace();
                char separator = take();
                if (separator == close) break;
                if (separator != ',') fail();
            }
        } else if (ch == 't' || ch == 'f' || ch == 'n') {
            const std::string literal = ch == 't' ? "true" : ch == 'f' ? "false" : "null";
            if (input.compare(pos, literal.size(), literal) != 0) fail();
            pos += literal.size();
        } else {
            out.kind = 'N';
            if (input[pos] == '-') ++pos;
            if (pos == input.size() || !std::isdigit(static_cast<unsigned char>(input[pos]))) fail();
            if (input[pos] == '0') ++pos;
            else while (pos < input.size() && std::isdigit(static_cast<unsigned char>(input[pos]))) ++pos;
            for (char marker : {'.', 'e'}) {
                if (pos < input.size() && (input[pos] == marker || (marker == 'e' && input[pos] == 'E'))) {
                    ++pos;
                    if (marker == 'e' && pos < input.size() && (input[pos] == '+' || input[pos] == '-')) ++pos;
                    std::size_t digits = pos;
                    while (pos < input.size() && std::isdigit(static_cast<unsigned char>(input[pos]))) ++pos;
                    if (digits == pos) fail();
                }
            }
        }
        out.text = input.substr(start, pos - start);
        return out;
    }
public:
    explicit Parser(const std::string& document, std::size_t max_bytes = 8 * 1024 * 1024) : input(document) {
        if (max_bytes > 20 * 1024 * 1024 || input.size() > max_bytes) fail();
    }
    Value parse() {
        Value out = value(0);
        whitespace();
        if (pos != input.size() || out.kind != '{') fail();
        return out;
    }
};

inline Value field(const std::string& document, const std::string& name, char kind) {
    Value root = Parser(document).parse();
    auto found = root.fields.find(name);
    if (found == root.fields.end() || found->second.kind != kind)
        throw std::invalid_argument("missing or wrong-type fixture field: " + name);
    return found->second;
}
inline std::uint64_t uint64(const std::string& text) {
    if (text.empty() || text.size() > 20) throw std::invalid_argument("invalid unsigned integer");
    for (char ch : text) if (ch < '0' || ch > '9') throw std::invalid_argument("invalid unsigned integer");
    return std::stoull(text);
}
} // namespace cr01::fixture
