// Fresh process per invocation. No provider/control warm-up before first use.
#include "channel_v2_endpoint.hpp"
#include "lifecycle_profile.hpp"
#include <iomanip>
#include <iostream>
#include <set>
#include <vector>
using namespace cr01::channel;
using Timer = std::chrono::steady_clock;
double elapsed(Timer::time_point start) { return std::chrono::duration<double,std::milli>(Timer::now()-start).count(); }
Key retain(EVP_PKEY* key) { if (EVP_PKEY_up_ref(key) != 1) reject(); return Key(key, EVP_PKEY_free); }
struct Pair {
    Endpoint i, r;
    Pair(EVP_PKEY* a, EVP_PKEY* b)
      : i("initiator",retain(a),public_bytes(b,1952),bytes("lifecycle-benchmark"),1),
        r("responder",retain(b),public_bytes(a,1952),bytes("lifecycle-benchmark"),1) {}
    std::string handshake() {
        auto a=i.start(), b=r.respond(a), c=i.finish(b), d=r.accept(c); i.confirm(d);
        if (i.session_id()!=r.session_id() || i.phase()!="established" || r.phase()!="established") reject();
        return hex(i.session_id());
    }
};
void emit(const char* name, const std::vector<double>& samples) {
    std::cout << '"' << name << "\":{\"raw_ms\":[";
    for (std::size_t n=0;n<samples.size();++n) { if(n)std::cout<<','; std::cout<<samples[n]; }
    std::cout << "],\"profile\":"; lifecycle_profile::emit(std::cout); std::cout << '}';
}
int main(int argc, char** argv) {
    try {
        if (argc!=4) reject();
        const int count=std::stoi(argv[3]); if(count<2 || count>200)reject();
        cr01::memory::restrict_process_dumps();
        std::cout << std::setprecision(12) << "{\"openssl\":\"" << OpenSSL_version(OPENSSL_VERSION) << "\",";
        auto start=Timer::now(); auto a=load_identity(argv[1]), b=load_identity(argv[2]);
        emit("identity_load",{elapsed(start)}); std::cout << ','; lifecycle_profile::reset();
        std::set<std::string> sessions;
        start=Timer::now(); { Pair p(a.get(),b.get()); if(!sessions.insert(p.handshake()).second)reject(); }
        emit("warm_up",{elapsed(start)}); std::cout << ','; lifecycle_profile::reset();
        // Two more disclosed, untimed conditioning handshakes, not hidden samples.
        for(int n=0;n<2;++n) { Pair p(a.get(),b.get()); if(!sessions.insert(p.handshake()).second)reject(); }
        lifecycle_profile::reset(); std::vector<double> samples;
        for(int n=0;n<count;++n) {
            start=Timer::now(); Pair p(a.get(),b.get()); auto id=p.handshake(); samples.push_back(elapsed(start));
            if(!sessions.insert(id).second)reject();
        }
        emit("fresh_handshake",samples); std::cout << ','; lifecycle_profile::reset();
        Pair p(a.get(),b.get()); if(!sessions.insert(p.handshake()).second)reject();
        for(auto size : {std::size_t{1024},std::size_t{1048576}}) {
            Bytes data(size,0x5a); const Bytes aad=bytes("lifecycle");
            Bytes frame;
            const auto roundtrip=[&](int n) {
                auto& sender=n%2 ? p.r:p.i; auto& receiver=n%2 ? p.i:p.r;
                sender.send_into(data,aad,frame);
                auto received=receiver.receive_owned(std::move(frame),&aad);
                if(!std::ranges::equal(received.view(),data))reject();
                frame=received.take_cleansed_storage();
            };
            for(int n=0;n<5;++n)roundtrip(n);
            lifecycle_profile::reset(); samples.clear();
            for(int n=0;n<30;++n) { start=Timer::now();roundtrip(n);samples.push_back(elapsed(start)); }
            emit(size==1024 ? "running_1k":"running_1m",samples); std::cout << ',';
        }
        std::cout << "\"unique_sessions\":" << sessions.size() << "}\n";
    } catch(const std::exception&) { std::cerr<<"lifecycle diagnostic rejected\n"; return 1; }
}
