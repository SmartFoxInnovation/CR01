#pragma once
// Diagnostic build only. Fixed labels, durations and counts; never crypto values.
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <ostream>
#include <stdexcept>
namespace lifecycle_profile {
using Clock = std::chrono::steady_clock;
struct Node { const char* name = ""; std::uint64_t calls = 0, inclusive = 0, self = 0; };
inline std::array<Node, 64> nodes{};
inline unsigned used = 0, depth = 0;
inline bool valid = true;
inline std::array<std::uint64_t, 64> children{};
inline void reset() { if (depth) throw std::runtime_error("active profiler reset"); nodes = {}; used = 0; valid = true; }
class Scope {
    unsigned node_ = 0, depth_ = 0;
    Clock::time_point start_;
public:
    explicit Scope(const char* name) {
        for (; node_ < used && std::strcmp(nodes[node_].name, name); ++node_) {}
        if (node_ == used) {
            if (used == nodes.size()) throw std::runtime_error("profile label bound");
            nodes[used++].name = name;
        }
        if (depth == children.size()) throw std::runtime_error("profile depth bound");
        depth_ = depth++; children[depth_] = 0; start_ = Clock::now();
    }
    ~Scope() noexcept {
        const auto ns = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now()-start_).count());
        if (!depth || --depth != depth_ || children[depth_] > ns) { valid = false; return; }
        auto& n = nodes[node_]; ++n.calls; n.inclusive += ns; n.self += ns - children[depth_];
        if (depth_) children[depth_-1] += ns;
    }
    Scope(const Scope&) = delete;
};
template<class F> auto call(const char* name, F operation) { Scope scope(name); return operation(); }
inline void emit(std::ostream& out) {
    out << "{\"accounting_valid\":" << (valid && !depth ? "true" : "false") << ",\"nodes\":[";
    for (unsigned n = 0; n < used; ++n) {
        if (n) out << ',';
        out << "{\"name\":\"" << nodes[n].name << "\",\"calls\":" << nodes[n].calls
            << ",\"inclusive_ns\":" << nodes[n].inclusive << ",\"self_ns\":" << nodes[n].self << '}';
    }
    out << "]}";
}
}
