#define CR01_CHANNEL_TESTING
#include "../../../src/cpp/channel_v2_endpoint.hpp"
#include <atomic>
#include <iostream>
#include <thread>
#include <type_traits>
#include <random>

namespace cr01::channel {
// Test-only friend. These controls are absent from the production app build.
struct EndpointTestAccess {
    static void handshake_expired(Endpoint& e) { e.born_ -= std::chrono::seconds(120); }
    static void handshake_clock_backwards(Endpoint& e) { e.last_ += std::chrono::seconds(10); }
    static void wrong_pid(Endpoint& e) { ++e.pid_; }
    static void session_expired(Endpoint& e) { e.session_->born -= std::chrono::seconds(3600); }
    static void session_clock_backwards(Endpoint& e) { e.session_->last += std::chrono::seconds(10); }
    static void send_exhausted(Endpoint& e) { e.session_->next = v2::kMaxMessages + 1; }
    static void receive_exhausted(Endpoint& e) { e.session_->received = v2::kMaxMessages; }
    static bool nonce_burns_on_error(Endpoint& e) {
        auto old = e.session_->next;
        e.fail_next_send_ = true;
        bool rejected = false;
        try { e.send(bytes("not emitted"), {}); } catch (const std::exception&) { rejected = true; }
        return rejected && e.session_->next == old + 1;
    }
};
}

static_assert(!std::is_copy_constructible_v<cr01::channel::Endpoint>);
static_assert(!std::is_move_constructible_v<cr01::channel::Endpoint>);
static_assert(!std::is_copy_assignable_v<cr01::channel::Endpoint>);
static_assert(!std::is_move_assignable_v<cr01::channel::Endpoint>);
static_assert(!std::is_copy_constructible_v<cr01::v2::RecordCipher>);
static_assert(!std::is_move_constructible_v<cr01::v2::RecordCipher>);
static_assert(!std::is_copy_constructible_v<cr01::v2::AuthenticatedRecord>);
static_assert(!std::is_copy_assignable_v<cr01::v2::AuthenticatedRecord>);
static_assert(!std::is_constructible_v<cr01::v2::AuthenticatedRecord,std::size_t>);
static_assert(std::is_nothrow_move_constructible_v<cr01::v2::AuthenticatedRecord>);
static_assert(std::is_same_v<decltype(std::declval<cr01::v2::AuthenticatedRecord>().view()),std::span<const unsigned char>>);

namespace cr01::v2 {
struct PlaintextTestAccess {
    static void observe(void (*callback)(std::span<const unsigned char>) noexcept) { AuthenticatedRecord::after_wipe_=callback; }
    static void fail_partial() {
        AuthenticatedRecord partial(record::Bytes(65),0,64);
        std::fill_n(partial.storage_.data(),17,0xa5);
        throw std::invalid_argument("injected private-output failure");
    }
};
}

int main() {
    using namespace cr01::channel;
    namespace record = cr01::record;
    namespace v2 = cr01::v2;
    unsigned passed = 0, total = 0;
    unsigned codec_cases = 0, codec_passed = 0;
    const auto check = [&](bool okay) { ++total; if (okay) ++passed; };
    const auto rejects = [&](auto action) { try { action(); check(false); } catch (const std::exception&) { check(true); } };
    try {
        auto ikey = generate("ML-DSA-65"), rkey = generate("ML-DSA-65");
        const auto clone = [](EVP_PKEY* key) { if (EVP_PKEY_up_ref(key) != 1) reject(); return Key(key, EVP_PKEY_free); };
        const auto pair = [&] {
            return std::make_pair(
                std::make_unique<Endpoint>("initiator", clone(ikey.get()), public_bytes(rkey.get(), 1952), bytes("unit"), 1),
                std::make_unique<Endpoint>("responder", clone(rkey.get()), public_bytes(ikey.get(), 1952), bytes("unit"), 1));
        };
        const auto establish_pair = [](Endpoint& i, Endpoint& r) {
            auto hello = i.start(); auto reply = r.respond(hello); auto finish = i.finish(reply);
            auto ack = r.accept(finish); i.confirm(ack);
        };
        auto [i, r] = pair();
        rejects([&] { i->send(bytes("early"), {}); });
        establish_pair(*i, *r);
        check(i->session_id() == r->session_id());
        check(r->receive(i->send(bytes("forward"), {})) == bytes("forward"));
        check(i->receive(r->send(bytes("reverse"), {})) == bytes("reverse"));
        check(r->receive(i->send({}, {})).empty());
        check(EndpointTestAccess::nonce_burns_on_error(*i));
        check(r->receive(i->send(bytes("after burned nonce"), {})) == bytes("after burned nonce"));
        auto frame = i->send(bytes("fresh"), bytes("aad"));
        auto bad = frame; bad.back() ^= 1;
        rejects([&] { r->receive(bad); });
        check(r->receive(frame) == bytes("fresh"));
        rejects([&] { r->receive(frame); });
        rejects([&] { i->receive(frame); });
        rejects([&] { i->send(Bytes(record::kMaxPayloadBytes + 1), {}); });
        rejects([&] { i->send({}, Bytes(record::kMaxAadBytes + 1)); });
        rejects([&] { r->receive(Bytes(10)); });
        std::vector<Bytes> frames;
        for (unsigned n = 0; n < 130; ++n) frames.push_back(i->send(bytes("window"), {}));
        for (unsigned n = 1; n < frames.size(); ++n) r->receive(frames[n]);
        rejects([&] { r->receive(frames.front()); });
        for (unsigned mode = 0; mode < 3; ++mode) {
            auto [a, b] = pair();
            if (mode == 0) EndpointTestAccess::handshake_expired(*a);
            else if (mode == 1) EndpointTestAccess::handshake_clock_backwards(*a);
            else EndpointTestAccess::wrong_pid(*a);
            rejects([&] { a->start(); });
        }
        for (unsigned mode = 0; mode < 5; ++mode) {
            auto [a, b] = pair(); establish_pair(*a, *b);
            if (mode == 0) EndpointTestAccess::session_expired(*a);
            else if (mode == 1) EndpointTestAccess::session_clock_backwards(*a);
            else if (mode == 2) EndpointTestAccess::send_exhausted(*a);
            else if (mode == 3) EndpointTestAccess::wrong_pid(*a);
            else a->close();
            rejects([&] { a->send({}, {}); });
        }
        auto [a, b] = pair(); establish_pair(*a, *b);
        EndpointTestAccess::receive_exhausted(*b);
        rejects([&] { b->receive(a->send({}, {})); });
        rejects([&] { Endpoint("initiator", clone(ikey.get()), public_bytes(ikey.get(), 1952), bytes("unit"), 1); });
        rejects([&] { Endpoint("other-role", clone(ikey.get()), public_bytes(rkey.get(), 1952), bytes("unit"), 1); });
        rejects([&] { Endpoint("initiator", clone(ikey.get()), public_bytes(rkey.get(), 1952), {}, 1); });
        rejects([&] { Endpoint("initiator", clone(ikey.get()), public_bytes(rkey.get(), 1952), bytes("unit"), 0); });
        auto [c, d] = pair(); establish_pair(*c, *d);
        std::vector<Bytes> concurrent(32);
        std::vector<std::thread> threads;
        std::atomic<unsigned> failures{0}, accepted{0};
        for (unsigned n = 0; n < 32; ++n) threads.emplace_back([&, n] {
            try { concurrent[n] = c->send(bytes("concurrent"), {}); } catch (...) { ++failures; }
        });
        for (auto& thread : threads) thread.join();
        check(failures == 0);
        std::set<std::uint64_t> sequences;
        for (const auto& item : concurrent) sequences.insert(v2::get_be(item, 21, 8));
        check(sequences.size() == 32);
        threads.clear();
        for (unsigned n = 0; n < 16; ++n) threads.emplace_back([&] {
            try { d->receive(concurrent.front()); ++accepted; } catch (const std::exception&) {}
        });
        for (auto& thread : threads) thread.join();
        check(accepted == 1);
        // Independent previous parser/printer is the grammar oracle. Restrict
        // it to the flat scalar envelope that v2 actually permits, then compare
        // 3000 fixed-seed mutations plus truncation/whitespace cases.
        const auto old_grammar = [](const Bytes& frame) {
            try {
                if(frame.empty()||frame.size()>32768)reject();
                auto encoded=text(frame);auto root=cr01::fixture::Parser(encoded).parse();
                if(dump(root)!=encoded)reject();
                exact_fields(root.fields,{"payload","signature"});
                const auto& payload=root.fields.at("payload");
                if(payload.kind!='{'||payload.fields.size()>12)reject();
                for(const auto& [key,value]:payload.fields) {
                    (void)key;if(value.kind!='"'&&value.kind!='N')reject();
                }
                field_hex(root.fields,"signature",3309);return true;
            } catch(const std::exception&) { return false; }
        };
        const auto new_grammar = [](const Bytes& frame) {
            try { auto p=FlightReader(frame).parse();unhex(p.signature,3309,3309);return true; }
            catch(const std::exception&) { return false; }
        };
        const auto compare_grammars = [&](const Bytes& candidate) {
            ++codec_cases;if(old_grammar(candidate)==new_grammar(candidate))++codec_passed;
        };
        auto [codec_i,codec_r]=pair();
        auto h=codec_i->start(),reply=codec_r->respond(h),finish=codec_i->finish(reply);
        std::mt19937 rng(15002);
        for(const auto& original:{h,reply,finish}) {
            auto view=FlightReader(original).parse();
            auto parsed=cr01::fixture::Parser(text(original)).parse();
            check(view.encoded==dump(parsed.fields.at("payload")));
            check(flight_signature_input(view.encoded)==joined(domain(),packed({bytes(dump(parsed.fields.at("payload")))})));
            check(flight_envelope(view.encoded,unhex(view.signature,3309,3309))==original);
            compare_grammars(original);
            for(unsigned n=0;n<1000;++n) {
                auto candidate=original;candidate[rng()%candidate.size()]=static_cast<unsigned char>(rng()%256);
                compare_grammars(candidate);
            }
            for(std::size_t cut:{std::size_t(0),std::size_t(1),std::size_t(11),original.size()-1})
                compare_grammars(Bytes(original.begin(),original.begin()+cut));
            compare_grammars(joined(bytes(" "),original));
            compare_grammars(joined(original,bytes(" ")));
        }
        check(codec_cases>=3000 && codec_passed==codec_cases);
        check(hash_flights({h,reply,finish})==hash(joined(domain(),packed({h,reply,finish}))));
        check(hash_flights({Bytes{},h,Bytes{}})==hash(joined(domain(),packed({Bytes{},h,Bytes{}}))));
        Bytes public_secret(32,0x17),public_salt(32,0x25);
        auto public_prk=record::hmac_sha256(public_salt,public_secret);
        Secret protected_prk(public_prk.size());
        std::copy(public_prk.begin(),public_prk.end(),protected_prk.data());
        auto old_info=joined(domain(),bytes("initiator-traffic"));old_info.push_back(1);
        check(std::ranges::equal(expand_label(protected_prk,"initiator-traffic").view(),record::hmac_sha256(public_prk,old_info)));
        // Cached keyed contexts must produce exactly the existing v2 bytes.
        // Independent old-style contiguous-AAD primitive path is the oracle.
        const Bytes public_key(32, 0x42), public_sid(16, 0x35);
        v2::RecordCipher enc(public_key, true), dec(public_key, false);
        std::uint64_t seq = 0;
        Bytes reused;
        for (std::size_t size : {0U,1U,15U,16U,17U,1024U,16383U,16384U,16385U,32767U,32768U,32769U,65536U,1048575U,1048576U,1048577U}) {
            Bytes data(size, static_cast<unsigned char>(size)), aad(size%2 ? 65536 : 7, 0xa5);
            auto f = v2::seal(enc, public_sid, 0, ++seq, data, aad);
            rejects([&]{ v2::open(enc,public_sid,0,f); });
            rejects([&]{ v2::seal(dec,public_sid,0,seq+1,data,aad); });
            Bytes header(f.begin(),f.begin()+v2::kHeader);
            auto [ct,tag] = record::aes_gcm_encrypt(public_key,v2::nonce(seq),data,v2::aad(header,aad));
            record::append(header,aad);record::append(header,ct);record::append(header,tag);
            check(f == header);
            auto original_data=data,original_aad=aad;
            v2::seal_into(enc,public_sid,0,seq,data,aad,reused);
            check(reused==f);
            check(data==original_data && aad==original_aad);
            const auto storage=reused.data();
            v2::seal_into(enc,public_sid,0,seq,data,aad,reused);
            check(reused==f && reused.data()==storage);
            auto original_frame=f;
            for (std::size_t offset : {std::size_t(37), f.size()-1}) {
                auto invalid=f;invalid[offset]^=1;
                rejects([&]{ v2::open(dec,public_sid,1,invalid); }); // wrong direction
                rejects([&]{ v2::open(dec,public_sid,0,invalid); }); // bad AAD/tag
                check(v2::open(dec,public_sid,0,f)==data);
                check(f==original_frame);
            }
            check(v2::open(dec,public_sid,0,v2::seal(enc,public_sid,0,++seq,{},{})).empty());
        }
        Bytes public_input(31,0x45),public_aad(7,0x54),public_id=public_sid;
        rejects([&]{v2::seal_into(enc,public_id,0,++seq,public_input,public_aad,public_input);});
        check(public_input==Bytes(31,0x45));
        reused=Bytes(1024,0x33);
        rejects([&]{v2::seal_into(dec,public_id,0,++seq,public_input,public_aad,reused);});
        check(reused.empty());
        auto [reuse_i,reuse_r]=pair();establish_pair(*reuse_i,*reuse_r);
        Bytes reuse_frame;
        reuse_i->send_into(bytes("caller-owned"),{},reuse_frame);
        check(reuse_r->receive(reuse_frame)==bytes("caller-owned"));
        auto capacity=reuse_frame.capacity();
        reuse_i->send_into(bytes("caller-owned"),{},reuse_frame);
        check(reuse_r->receive(reuse_frame)==bytes("caller-owned") && reuse_frame.capacity()==capacity);
        // Observe live storage only AFTER cleansing and BEFORE free. No freed
        // pointer reads, keys, addresses or plaintext are printed or retained.
        static std::size_t wipes=0,wiped_bytes=0;
        static bool all_zero=true;
        v2::PlaintextTestAccess::observe(+[](std::span<const unsigned char> value) noexcept {
            ++wipes;wiped_bytes+=value.size();
            for(auto ch:value) if(ch!=0) all_zero=false;
        });
        for(std::size_t size:{0U,1U,15U,16U,17U,16383U,16384U,16385U,65536U,1048575U,1048576U,1048577U,8388608U}) {
            Bytes data(size,0x5c),aad(size%2?7:65536,0x13);
            auto frame=v2::seal(enc,public_sid,0,++seq,data,aad),original=frame;
            auto previous=wipes;
            {
                auto plain=v2::open_owned(dec,public_sid,0,frame);
                check(std::ranges::equal(plain.view(),data));
                auto moved=std::move(plain);
                check(plain.view().empty() && std::ranges::equal(moved.view(),data));
                auto replacement=v2::open_owned(dec,public_sid,0,frame);
                replacement=std::move(moved);
                check(moved.view().empty() && std::ranges::equal(replacement.view(),data));
                const auto move_assign=[](auto& target,auto& source) { target=std::move(source); };
                move_assign(replacement,replacement); // Exercise the alias case without a self-move warning.
                check(std::ranges::equal(replacement.view(),data));
            }
            check(wipes==previous+2 && all_zero);
            check(frame==original && v2::open(dec,public_sid,0,frame)==data);
            auto corrupt=frame;corrupt.back()^=1;
            previous=wipes;bool exposed=false;
            try { auto rejected=v2::open_owned(dec,public_sid,0,corrupt);exposed=true; }
            catch(const std::exception&) {}
            check(!exposed && wipes==previous+1 && all_zero);
            rejects([&]{v2::open_owned(enc,public_sid,0,frame);});
            check(wipes==previous+1); // Wrong mode rejects before allocation.
            auto consumed=frame;const auto storage=consumed.data();
            auto owned=v2::open_owned(dec,public_sid,0,std::move(consumed));
            check(consumed.empty() && owned.view().data()==storage+v2::kHeader+aad.size());
            auto cleared=owned.take_cleansed_storage();
            check(owned.view().empty() && cleared.data()==storage && cleared.size()==frame.size());
            check(std::ranges::all_of(cleared,[](auto ch){return ch==0;}));
        }
        auto previous=wipes;rejects([&]{v2::PlaintextTestAccess::fail_partial();});
        check(wipes==previous+1 && wiped_bytes>0 && all_zero);
        auto [owned_i,owned_r]=pair();establish_pair(*owned_i,*owned_r);
        auto owned_frame=owned_i->send(bytes("owned"),bytes("binding"));
        auto owned_bad=owned_frame;owned_bad.back()^=1;
        rejects([&]{owned_r->receive_owned(owned_bad);});
        auto owned=owned_r->receive_owned(owned_frame);
        check(std::ranges::equal(owned.view(),bytes("owned")));
        rejects([&]{owned_r->receive_owned(owned_frame);});
        auto next=owned_r->receive_owned(owned_i->send(bytes("next"),{}));
        owned_r->close();
        check(std::ranges::equal(owned.view(),bytes("owned")) && std::ranges::equal(next.view(),bytes("next")));
        v2::PlaintextTestAccess::observe(nullptr);
    } catch (const std::exception&) { check(false); }
    std::cout << "{\"passed\":" << passed << ",\"total\":" << total
              << ",\"codec_differential_cases\":" << codec_cases << ",\"codec_differential_passed\":" << codec_passed << "}\n";
    return passed == total ? 0 : 1;
}
