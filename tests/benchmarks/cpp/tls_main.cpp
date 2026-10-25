#include "tls_support.hpp"
#include <chrono>
#include <iomanip>
#include <numeric>

namespace {
using namespace compare;
using Clock=std::chrono::steady_clock;
double elapsed(Clock::time_point begin) { return std::chrono::duration<double,std::milli>(Clock::now()-begin).count(); }
void statistics(std::vector<double> samples) {
    auto sorted=samples; std::sort(sorted.begin(),sorted.end());
    std::cout << "\"samples\":" << samples.size() << ",\"mean_ms\":"
      << std::accumulate(samples.begin(),samples.end(),0.0)/samples.size()
      << ",\"p50_ms\":" << sorted[(sorted.size()-1)/2]
      << ",\"p95_ms\":" << sorted[(sorted.size()*95+99)/100-1] << ",\"raw_ms\":[";
    bool first=true;
    for (double value:samples) { if (!first) std::cout << ','; first=false; std::cout << value; }
    std::cout << ']';
}
Bytes seal(Endpoint& peer,const Bytes& data) { return peer.send(data,{}); }
template<class T> Bytes seal(T& peer,const Bytes& data) { return peer.send(data); }
template<class T> void seal_output(T& peer,const Bytes& data,Bytes& output) {
    // Same logical record operation; prefer the additive caller-owned output
    // API when present. Preserved older CR01 sources use their returning API.
    if constexpr(requires { peer.send_into(data,Bytes{},output); }) peer.send_into(data,{},output);
    else output=seal(peer,data);
}
template<class T> void checked_receive(T& peer,Bytes& frame,const Bytes& expected) {
    if constexpr(requires { peer.receive_owned(std::move(frame)); }) {
        auto plain=peer.receive_owned(std::move(frame));require(std::ranges::equal(plain.view(),expected),"owned plaintext");
        frame=plain.take_cleansed_storage();
    } else { auto plain=peer.receive(frame);require(plain==expected,"plaintext"); }
    // Owner destruction, cleansing and plaintext checking stay INSIDE timing.
}
std::size_t fragments(const Bytes& frame) {
    std::size_t offset=0,count=0;
    while (offset<frame.size()) {
        require(frame.size()-offset>=5,"TLS wire header");
        auto n=(std::size_t(frame[offset+3])<<8)|frame[offset+4];
        require(offset+5+n<=frame.size(),"TLS wire length"); offset+=5+n; ++count;
    }
    return count;
}
template<class Pair> void records(Pair& pair,bool tls,bool quick) {
    std::cout << "\"records\":["; bool first=true;
    for (auto [size,count]: {std::pair<std::size_t,int>{64,5000},{1024,5000},{16384,5000},{65536,1000},{1048576,100}}) {
        if (quick) count=10;
        Bytes data(size,0x5a); std::vector<double> times; times.reserve(count);
        for (unsigned j=0;j<10;++j) require(pair.r.receive(seal(pair.i,data))==data,"record warmup plaintext");
        std::size_t encoded=0,parts=1; Bytes frame;
        for (int j=0;j<count;++j) {
            auto& sender=j%2 ? pair.r : pair.i; auto& receiver=j%2 ? pair.i : pair.r;
            auto begin=Clock::now(); seal_output(sender,data,frame); checked_receive(receiver,frame,data);
            times.push_back(elapsed(begin));
            encoded=frame.size(); if (j==0 && tls) parts=fragments(frame);
        }
        if (!first) std::cout << ',';
        first=false;
        std::cout << "{\"payload_bytes\":" << size << ",\"encoded_bytes\":" << encoded
          << ",\"fragments\":" << parts << ','; statistics(times); std::cout << '}';
    }
    std::cout << ']';
}
struct AesPair {
    Aes i,r;
    AesPair(const Bytes& a,const Bytes& b,bool reuse) : i(a,b,reuse),r(b,a,reuse) {}
};
template<class F> bool rejects(F action) { try { action(); return false; } catch (const std::exception&) { ERR_clear_error(); return true; } }
std::map<std::string,bool> controls(const std::string& profile,const std::filesystem::path& dir) {
    std::map<std::string,bool> results;
    const auto data=bytes("verified diagnostic plaintext");
    if (profile.rfind("tls-",0)==0) {
        auto credentials=dir/(profile=="tls-pq" ? "pq" : "ec"); TlsConfig cfg(credentials,profile);
        { TlsPair p(cfg); p.handshake(); auto f=p.i.send(data); results["valid_roundtrip"]=p.r.receive(f)==data; }
        { TlsConfig bad(credentials,profile,false); results["untrusted_ca_rejected"]=rejects([&]{ TlsPair p(bad); p.handshake(); }); }
        results["wrong_hostname_rejected"]=rejects([&]{ TlsPair p(cfg,true); p.handshake(); });
        { TlsConfig missing(credentials,profile,true,false); results["missing_client_certificate_rejected"]=rejects([&]{TlsPair p(missing);p.handshake();}); }
        { TlsPair p(cfg);p.handshake();auto f=p.i.send(data);f.back()^=1;results["bad_tag_rejected"]=rejects([&]{p.r.receive(f);}); }
        { TlsPair p(cfg);p.handshake();auto f=p.i.send(data);p.r.receive(f);results["replayed_record_rejected"]=rejects([&]{p.r.receive(f);}); }
    } else if (profile=="cr01") {
        auto a=generate("ML-DSA-65"),b=generate("ML-DSA-65"),unknown=generate("ML-DSA-65");
        { CrPair p(a.get(),b.get());p.handshake(); auto f=p.i.send(data,{});auto bad=f;bad.back()^=1;
          results["bad_tag_rejected"]=rejects([&]{p.r.receive(bad);});
          results["valid_after_bad_tag"]=p.r.receive(f)==data;
          results["replayed_record_rejected"]=rejects([&]{p.r.receive(f);}); }
        results["wrong_peer_pin_rejected"]=rejects([&]{
            Endpoint i("initiator",retained(a.get()),public_bytes(b.get(),1952),bytes("test"),1);
            Endpoint r("responder",retained(b.get()),public_bytes(unknown.get(),1952),bytes("test"),1);r.respond(i.start()); });
    } else {
        auto a=random_bytes(32),b=random_bytes(32); AesPair p(a,b,profile=="aes-reuse"); auto f=p.i.send(data),bad=f;bad.back()^=1;
        results["bad_tag_rejected"]=rejects([&]{p.r.receive(bad);});
        results["valid_roundtrip"]=p.r.receive(f)==data;
        results["replay_accepted_expected_primitive_limit"]=p.r.receive(f)==data;
    }
    for (const auto& [name,okay]:results) require(okay,name.c_str());
    return results;
}
void bench(const std::string& profile,const std::filesystem::path& dir,bool quick) {
    auto tests=controls(profile,dir);
    std::cout << std::setprecision(12) << "{\"profile\":\"" << profile << "\",\"panel\":\"in-process\",\"openssl\":\""
      << OpenSSL_version(OPENSSL_VERSION) << "\",\"controls\":{"; bool first=true;
    for (auto [name,okay]:tests) { if (!first) std::cout << ',';first=false;std::cout << '"' << name << "\":" << (okay?"true":"false"); }
    std::cout << "},";
    std::vector<double> times; std::size_t wire=0; const int count=quick?2:30;
    if (profile=="cr01") {
        auto a=generate("ML-DSA-65"),b=generate("ML-DSA-65");
        for (int n=-3;n<count;++n) {auto begin=Clock::now();CrPair p(a.get(),b.get());wire=p.handshake();double ms=elapsed(begin);if(n>=0)times.push_back(ms);}
        std::cout << "\"handshake\":{";statistics(times);std::cout << ",\"wire_bytes\":" << wire << "},";
        CrPair p(a.get(),b.get());p.handshake();records(p,false,quick);
    } else if (profile.rfind("tls-",0)==0) {
        TlsConfig cfg(dir/(profile=="tls-pq"?"pq":"ec"),profile);
        for (int n=-3;n<count;++n) {auto begin=Clock::now();TlsPair p(cfg);wire=p.handshake();double ms=elapsed(begin);if(n>=0)times.push_back(ms);}
        std::cout << "\"handshake\":{";statistics(times);std::cout << ",\"wire_bytes\":" << wire << "},";
        TlsPair p(cfg);p.handshake();std::cout << "\"negotiated\":" << p.i.details() << ',';records(p,true,quick);
    } else {
        auto a=random_bytes(32),b=random_bytes(32); AesPair p(a,b,profile=="aes-reuse");
        std::cout << "\"handshake\":null,";records(p,false,quick);
    }
    std::cout << "}\n";
}
void primitive(bool quick) {
    // True primitive lower-cost measurement: reused keyed EVP contexts and
    // preallocated buffers; no packet framing, endpoint checks, heap work or IPC.
    auto key=random_bytes(32);
    std::unique_ptr<EVP_CIPHER_CTX,decltype(&EVP_CIPHER_CTX_free)> enc(EVP_CIPHER_CTX_new(),EVP_CIPHER_CTX_free),
        dec(EVP_CIPHER_CTX_new(),EVP_CIPHER_CTX_free);
    require(enc && dec && EVP_EncryptInit_ex(enc.get(),EVP_aes_256_gcm(),nullptr,key.data(),nullptr)==1 &&
            EVP_DecryptInit_ex(dec.get(),EVP_aes_256_gcm(),nullptr,key.data(),nullptr)==1,"primitive context setup");
    std::array<unsigned char,12> iv{};std::array<unsigned char,16> tag{};std::uint64_t seq=0;
    std::cout << std::setprecision(12) << "{\"profile\":\"aes-primitive\",\"panel\":\"primitive-only\",\"openssl\":\""
       << OpenSSL_version(OPENSSL_VERSION) << "\",\"handshake\":null,\"framing_included\":false,\"records\":[";
    bool first=true;
    for (auto [size,count]: {std::pair<std::size_t,int>{64,5000},{1024,5000},{16384,5000},{65536,1000},{1048576,100}}) {
        if (quick) count=10;
        Bytes data(size,0x5a),ct(size+16),plain(size+16);std::vector<double> times;times.reserve(count);
        for (int index=-10;index<count;++index) {
            ++seq;for (unsigned n=0;n<8;++n) iv[4+n]=static_cast<unsigned char>(seq>>(56-8*n));
            int written=0,tail=0,opened=0,end=0;
            auto start=Clock::now();
            require(EVP_EncryptInit_ex(enc.get(),nullptr,nullptr,nullptr,iv.data())==1 &&
                    EVP_EncryptUpdate(enc.get(),ct.data(),&written,data.data(),static_cast<int>(size))==1 &&
                    EVP_EncryptFinal_ex(enc.get(),ct.data()+written,&tail)==1 &&
                    EVP_CIPHER_CTX_ctrl(enc.get(),EVP_CTRL_GCM_GET_TAG,16,tag.data())==1,"primitive encrypt");
            require(EVP_DecryptInit_ex(dec.get(),nullptr,nullptr,nullptr,iv.data())==1 &&
                    EVP_DecryptUpdate(dec.get(),plain.data(),&opened,ct.data(),written+tail)==1 &&
                    EVP_CIPHER_CTX_ctrl(dec.get(),EVP_CTRL_GCM_SET_TAG,16,tag.data())==1 &&
                    EVP_DecryptFinal_ex(dec.get(),plain.data()+opened,&end)==1,"primitive authenticate");
            double ms=elapsed(start);if(index>=0)times.push_back(ms);
            require(opened+end==static_cast<int>(size) && std::equal(data.begin(),data.end(),plain.begin()),"primitive plaintext");
        }
        // Untimed tag-failure control; this is not a channel/replay policy.
        tag.back()^=1;int opened=0,end=0;
        require(EVP_DecryptInit_ex(dec.get(),nullptr,nullptr,nullptr,iv.data())==1 &&
                EVP_DecryptUpdate(dec.get(),plain.data(),&opened,ct.data(),static_cast<int>(size))==1 &&
                EVP_CIPHER_CTX_ctrl(dec.get(),EVP_CTRL_GCM_SET_TAG,16,tag.data())==1 &&
                EVP_DecryptFinal_ex(dec.get(),plain.data()+opened,&end)!=1,"primitive bad tag control");
        ERR_clear_error();
        if (!first) std::cout << ',';
        first=false;std::cout << "{\"payload_bytes\":" << size << ",\"encoded_bytes\":0,\"fragments\":0,";
        statistics(times);std::cout << '}';
    }
    wipe(key);std::cout << "],\"controls\":{\"bad_tag_rejected\":true}}\n";
}
void app(const std::string& profile,const std::filesystem::path& dir,bool server) {
#ifdef _WIN32
    require(_setmode(_fileno(stdin),_O_BINARY)!=-1 && _setmode(_fileno(stdout),_O_BINARY)!=-1,"binary descriptor mode");
#endif
    std::ios::sync_with_stdio(false);std::cin.tie(nullptr);
    Context own_context(nullptr,SSL_CTX_free); Certificate expected_peer(nullptr,X509_free);
    std::unique_ptr<Tls> tls; std::unique_ptr<Aes> aes;
    if (profile.rfind("tls-",0)==0) {
        auto credentials=dir/(profile=="tls-pq"?"pq":"ec");
        own_context=context(credentials,profile,server);
        expected_peer=load_certificate(credentials/(server?"client.pem":"server.pem"));
        tls=std::make_unique<Tls>(own_context.get(),server,expected_peer.get(),profile);
    } else {
        auto material=read_regular(dir/"aes-keys.bin",64);require(material.size()==64,"AES diagnostic provision");
        Bytes a(material.begin(),material.begin()+32),b(material.begin()+32,material.end());
        aes=std::make_unique<Aes>(server?b:a,server?a:b,profile=="aes-reuse");wipe(material);wipe(a);wipe(b);
    }
    // Diagnostic ready has no identity payload. Established response metadata is
    // padded to 16 bytes for CRB1 overhead parity, NOT a TLS/AES session identifier.
    cr01::binary::emit(0,2,server?2:1,{},bytes(OpenSSL_version(OPENSSL_VERSION)));
    cr01::binary::Request request;
    while (cr01::binary::read_request(request)) {
        try {
            require(request.auxiliary.empty() && !request.flags,"diagnostic has no external AAD");
            Bytes data;
            if (request.operation==9) { cr01::binary::emit(9,0,7);return; }
            if (request.operation>=1 && request.operation<=5) { require(bool(tls),"AES has no handshake");data=tls->step(request.data); }
            else if (request.operation==6) data=tls ? tls->send(request.data) : aes->send(request.data);
            else if (request.operation==7) data=tls ? tls->receive(request.data) : aes->receive(request.data);
            else if (request.operation==8 && tls && tls->done()) data=bytes(tls->details());
            else require(request.operation==8,"diagnostic operation");
            bool done=aes || tls->done();cr01::binary::emit(request.operation,0,done?6:(server?4:3),data,done?Bytes(16,0):Bytes{});
        } catch (const std::exception&) { cr01::binary::rejected();return; }
    }
}
}
int main(int argc,char** argv) {
    try {
        require(argc>=4,"usage mode profile temporary-credential-directory [role/quick]");
        std::string mode=argv[1],profile=argv[2];std::filesystem::path dir=argv[3];
        if (mode=="provision") {provision(dir/"ec",false);provision(dir/"pq",true);return 0;}
        if (mode=="primitive") {primitive(argc==5 && std::string(argv[4])=="quick");return 0;}
        require(profile=="cr01" || profile=="tls-classical" || profile=="tls-hybrid" || profile=="tls-pq" || profile=="aes-reuse" || profile=="aes-fresh","unknown profile");
        if (mode=="bench") bench(profile,dir,argc==5 && std::string(argv[4])=="quick");
        else if (mode=="app") { require(argc==5,"app role");std::string role=argv[4];require(role=="initiator"||role=="responder","app role");app(profile,dir,role=="responder"); }
        else throw std::runtime_error("unknown diagnostic mode");
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "comparison diagnostic failed: " << error.what() << '\n';
        ERR_print_errors_fp(stderr);return 1;
    }
}

