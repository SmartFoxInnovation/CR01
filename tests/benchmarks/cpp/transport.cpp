// Reproducible owned-v2 endpoint benchmark; synthetic data, no network transport.
#include "channel_v2_endpoint.hpp"
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <numeric>

using namespace cr01::channel;
using Timer = std::chrono::steady_clock;
Key retain(EVP_PKEY* key) {
    if (EVP_PKEY_up_ref(key) != 1) reject();
    return Key(key, EVP_PKEY_free);
}
struct Pair {
    Endpoint i, r;
    Pair(EVP_PKEY* a, EVP_PKEY* b)
      : i("initiator", retain(a), public_bytes(b, 1952), bytes("bounded-v2-benchmark"), 1),
        r("responder", retain(b), public_bytes(a, 1952), bytes("bounded-v2-benchmark"), 1) {}
    std::size_t handshake() {
        auto ch = i.start(); auto sh = r.respond(ch); auto cf = i.finish(sh);
        auto sf = r.accept(cf); i.confirm(sf);
        if (i.session_id() != r.session_id()) reject();
        return ch.size() + sh.size() + cf.size() + sf.size();
    }
};
double elapsed(Timer::time_point start) { return std::chrono::duration<double, std::milli>(Timer::now() - start).count(); }
void stats(std::vector<double> samples) {
    double mean = std::accumulate(samples.begin(), samples.end(), 0.0) / samples.size();
    std::sort(samples.begin(), samples.end());
    const auto p95 = (samples.size() * 95 + 99) / 100 - 1;
    std::cout << "\"samples\":" << samples.size() << ",\"mean_ms\":" << mean
              << ",\"p50_ms\":" << samples[(samples.size()-1)/2] << ",\"p95_ms\":" << samples[p95];
}
int main() {
    try {
        std::cout << std::setprecision(12);
        auto a = generate("ML-DSA-65"), b = generate("ML-DSA-65");
        std::vector<double> keygen, hs;
        for (int j=0; j<10; ++j) { auto begin=Timer::now(); auto key=generate("ML-DSA-65"); keygen.push_back(elapsed(begin)); }
        std::size_t wire = 0;
        for (int j=-3; j<30; ++j) {
            auto begin=Timer::now(); Pair pair(a.get(), b.get()); wire=pair.handshake();
            double duration=elapsed(begin); if (j>=0) hs.push_back(duration);
        }
        std::cout << "{\"kind\":\"native-in-process\",\"identity_keygen\":{"; stats(keygen);
        std::cout << "},\"handshake\":{"; stats(hs); std::cout << ",\"wire_bytes\":" << wire << "},\"records\":[";
        Pair pair(a.get(), b.get()); pair.handshake();
        bool first=true;
        for (const auto& [size, count] : {std::pair<std::size_t,int>{64,10000}, {1024,10000}, {65536,1000}, {1048576,100}}) {
            Bytes data(size, 0x5a), aad=bytes("v2-bench");
            for (int j=0;j<30;++j) { auto frame=pair.i.send(data,aad); if (pair.r.receive(frame,&aad)!=data) reject(); }
            std::vector<double> samples; samples.reserve(count); std::size_t encoded=0; Bytes frame;
            for (int j=0;j<count;++j) {
                Endpoint& sender=j%2 ? pair.r : pair.i; Endpoint& receiver=j%2 ? pair.i : pair.r;
                auto begin=Timer::now(); sender.send_into(data,aad,frame);
                { auto plain=receiver.receive_owned(std::move(frame),&aad);if(!std::ranges::equal(plain.view(),data))reject();frame=plain.take_cleansed_storage(); }
                samples.push_back(elapsed(begin)); encoded=frame.size();
            }
            if (!first) std::cout << ',';
            first=false;
            std::cout << "{\"payload_bytes\":" << size << ",\"encoded_bytes\":" << encoded << ',';
            stats(samples); std::cout << '}';
        }
        std::cout << "]}\n";
        return 0;
    } catch (const std::exception&) { std::cerr << "diagnostic failed\n"; return 1; }
}
