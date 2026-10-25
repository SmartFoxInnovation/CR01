// Fault controls exist in this test translation unit, never in the app.
#define CR01_CHANNEL_TESTING
#include "../../../src/cpp/channel_v2_endpoint.hpp"
#include <algorithm>
#include <iostream>
#include <type_traits>

namespace cr01::memory {
struct SecretTestAccess {
    static void fail(unsigned mode) { Secret::fail_ = mode; }
    static std::size_t live() { return Secret::live_; }
    static void reset_allocations() { Secret::allocations_ = 0; }
    static std::size_t allocations() { return Secret::allocations_; }
    static void observe(void (*callback)(std::span<const unsigned char>) noexcept) { Secret::after_wipe_ = callback; }
};
}
static_assert(!std::is_copy_constructible_v<cr01::memory::Secret>);
static_assert(!std::is_copy_assignable_v<cr01::memory::Secret>);
static_assert(std::is_nothrow_move_constructible_v<cr01::memory::Secret>);
static_assert(std::is_nothrow_move_assignable_v<cr01::memory::Secret>);

int main(int argc, char** argv) {
    using namespace cr01::channel;
    using Access = cr01::memory::SecretTestAccess;
    unsigned total = 0, passed = 0;
    const auto check = [&](bool result) { ++total; if (result) ++passed; };
    const auto rejects = [&](auto action) { try { action(); check(false); } catch (const std::exception&) { check(true); } };
    try {
        if (argc < 2 || argc > 3) reject();
        const std::string mode(argv[1]);
        static bool zeroed = true;
        static unsigned wipes = 0;
        Access::observe(+[](std::span<const unsigned char> data) noexcept {
            ++wipes; zeroed = zeroed && std::ranges::all_of(data, [](auto value) { return value == 0; });
        });
        if (mode == "memory") {
            rejects([] { Secret invalid(0); });
            rejects([] { Secret invalid(65537); });
            {
                Secret first(32); std::fill_n(first.data(), first.size(), 0xa5);
                auto* original = first.data(); Secret second(std::move(first));
                check(first.empty() && second.data() == original && Access::live() == 1);
                Secret third(64); std::fill_n(third.data(), third.size(), 0x5a);
                const auto previous = wipes;
                third = std::move(second);
                check(second.empty() && third.data() == original && wipes == previous + 1 && Access::live() == 1);
                third.clear(); check(third.empty() && Access::live() == 0);
                third.clear(); check(Access::live() == 0);
            }
            for (unsigned fault = 1; fault <= 3; ++fault) {
                Access::fail(fault); rejects([] { Secret failing(32); }); Access::fail(0);
                check(Access::live() == 0);
            }
            try { Secret partial(32); std::fill_n(partial.data(), 32, 0xa5); throw std::runtime_error("injected"); }
            catch (const std::exception&) {}
            check(Access::live() == 0 && zeroed && wipes >= 5);
#ifndef _WIN32
            cr01::memory::restrict_process_dumps();
            rlimit limit{}; check(getrlimit(RLIMIT_CORE, &limit) == 0 && limit.rlim_cur == 0);
            check(prctl(PR_GET_DUMPABLE) == 0);
#endif
        } else if (mode == "kdf") {
            for (unsigned seed=0;seed<16;++seed) {
                Secret secret(32), material(128);
                std::fill_n(secret.data(),32,static_cast<unsigned char>(seed));
                std::fill_n(material.data(),128,0xa5);
                const Bytes transcript(32,static_cast<unsigned char>(seed+1));
                std::span<unsigned char> prk(material.data(),32), ikey(material.data()+32,32), rkey(material.data()+64,32);
                const auto reference_prk=cr01::record::hmac_sha256(transcript,secret.view());
                secret_hmac_into(transcript,secret.view(),prk);
                check(std::ranges::equal(prk,reference_prk));
                for(const auto& label : {"initiator-finished","responder-finished","initiator-traffic","responder-traffic"}) {
                    auto info=joined(domain(),bytes(label));info.push_back(1);
                    const auto reference_key=cr01::record::hmac_sha256(reference_prk,info);
                    expand_label_into(prk,label,ikey);
                    check(std::ranges::equal(ikey,reference_key));
                    const auto old_key=derive(secret,transcript,label);
                    check(std::ranges::equal(ikey,old_key.view()));
                    check(cr01::record::hmac_sha256(ikey,transcript)==cr01::record::hmac_sha256(old_key.view(),transcript));
                }
                expand_label_into(prk,"initiator-traffic",ikey);
                expand_label_into(prk,"responder-traffic",rkey);
                check(!std::ranges::equal(ikey,rkey));
                check(std::ranges::all_of(std::span(material.data()+96,32),[](auto b){return b==0xa5;}));
                for(auto size : {std::size_t{0},std::size_t{31},std::size_t{33}})
                    rejects([&] { secret_hmac_into(transcript,secret.view(),{material.data(),size}); });
            }
            for(auto size : {std::size_t{64},std::size_t{96}}) {
                for(unsigned fault=1;fault<=3;++fault) {
                    Access::fail(fault);rejects([&]{Secret failing(size);});Access::fail(0);
                    check(Access::live()==0);
                }
                try { Secret partial(size);std::fill_n(partial.data(),size,0xa5);throw std::runtime_error("injected"); }
                catch(const std::exception&) {}
                check(Access::live()==0 && zeroed);
            }
            auto a=generate("ML-DSA-65"),b=generate("ML-DSA-65");
            const auto clone=[](EVP_PKEY* k) { if(EVP_PKEY_up_ref(k)!=1)reject();return Key(k,EVP_PKEY_free); };
            Access::reset_allocations();
            {
                Endpoint i("initiator",clone(a.get()),public_bytes(b.get(),1952),bytes("kdf-slots"),1);
                Endpoint r("responder",clone(b.get()),public_bytes(a.get(),1952),bytes("kdf-slots"),1);
                auto reply=r.respond(i.start()), finish=i.finish(reply), ack=r.accept(finish);i.confirm(ack);
                check(i.session_id()==r.session_id());
                check(r.receive(i.send(bytes("kdf slots"),{}))==bytes("kdf slots"));
                check(Access::allocations()==8 && Access::live()==0);
            }
            check(zeroed);
        } else if (mode == "rng") {
            auto ikey = generate("ML-DSA-65"), rkey = generate("ML-DSA-65");
            const auto clone = [](EVP_PKEY* key) { if (EVP_PKEY_up_ref(key) != 1) reject(); return Key(key, EVP_PKEY_free); };
            const auto pair = [&] { return std::make_pair(
                std::make_unique<Endpoint>("initiator", clone(ikey.get()), public_bytes(rkey.get(),1952),bytes("rng-tests"),1),
                std::make_unique<Endpoint>("responder", clone(rkey.get()), public_bytes(ikey.get(),1952),bytes("rng-tests"),1)); };
            for (auto fault : {BackendFailure::Nonce, BackendFailure::Signature}) {
                auto [i,r] = pair(); backend_failure = fault;
                rejects([&] { i->start(); }); backend_failure = BackendFailure::None;
                check(i->phase() == "closed"); rejects([&] { i->start(); });
                rejects([&] { i->send(bytes("must not escape"),{}); });
                check(Access::live() == 0);
            }
            for (auto fault : {BackendFailure::Nonce, BackendFailure::KeyGeneration, BackendFailure::Signature}) {
                auto [i,r] = pair(); auto hello = i->start(); backend_failure = fault;
                rejects([&] { r->respond(hello); }); backend_failure = BackendFailure::None;
                check(r->phase() == "closed"); rejects([&] { r->respond(hello); });
                check(Access::live() == 0);
            }
            for (auto fault : {BackendFailure::Encapsulation, BackendFailure::Signature}) {
                auto [i,r] = pair(); auto reply = r->respond(i->start());
                backend_failure = fault;
                rejects([&] { i->finish(reply); }); backend_failure = BackendFailure::None;
                check(i->phase() == "closed" && Access::live() == 0 && zeroed);
                rejects([&] { i->finish(reply); });
            }
            if (argc == 3) {
                const std::filesystem::path identity_path(argv[2]);
                backend_failure = BackendFailure::KeyGeneration;
                rejects([&] { generate_identity_file(identity_path); });
                backend_failure = BackendFailure::None;
                check(!std::filesystem::exists(identity_path));
            }
            for (unsigned fault = 1; fault <= 3; ++fault) {
                auto [i,r] = pair(); auto reply = r->respond(i->start());
                Access::fail(fault); rejects([&] { i->finish(reply); }); Access::fail(0);
                check(i->phase() == "closed" && Access::live() == 0);
            }
            {
                auto [i,r] = pair(); auto reply = r->respond(i->start());
                auto finish = i->finish(reply); auto ack = r->accept(finish); i->confirm(ack);
                check(i->phase() == "established" && r->phase() == "established");
                check(r->receive(i->send(bytes("fresh after faults"),{})) == bytes("fresh after faults"));
                check(Access::live() == 0);
            }
            check(zeroed && wipes > 0);
        } else reject();
    } catch (const std::exception&) { ++total; }
    std::cout << "{\"total\":" << total << ",\"passed\":" << passed << "}\n";
    return passed == total && total > 0 ? 0 : 1;
}
