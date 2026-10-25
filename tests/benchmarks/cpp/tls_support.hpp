#pragma once
// Diagnostic adapters only. Included for reproduction, not production endpoints.
#include "channel_binary.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>

namespace compare {
using namespace cr01::channel;
using Certificate = std::unique_ptr<X509, decltype(&X509_free)>;
using Context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using Connection = std::unique_ptr<SSL, decltype(&SSL_free)>;
inline void require(bool yes, const char* message) { if (!yes) throw std::runtime_error(message); }
inline Key retained(EVP_PKEY* value) { require(EVP_PKEY_up_ref(value)==1,"key reference"); return Key(value,EVP_PKEY_free); }
inline Key identity(bool pq) {
    if (pq) return generate("ML-DSA-65");
    Key result(EVP_PKEY_Q_keygen(nullptr,nullptr,"EC","prime256v1"),EVP_PKEY_free);
    require(bool(result),"EC key generation"); return result;
}
inline void extension(X509* cert, X509* issuer, int id, const char* value) {
    X509V3_CTX ctx; X509V3_set_ctx(&ctx,issuer,cert,nullptr,nullptr,0);
    std::unique_ptr<X509_EXTENSION,decltype(&X509_EXTENSION_free)> ext(
        X509V3_EXT_conf_nid(nullptr,&ctx,id,value),X509_EXTENSION_free);
    require(ext && X509_add_ext(cert,ext.get(),-1)==1,"certificate extension");
}
inline Certificate certificate(EVP_PKEY* key, const char* name, long serial,
                               X509* issuer, EVP_PKEY* signer, bool pq, bool ca, bool server) {
    Certificate cert(X509_new(),X509_free); require(bool(cert),"certificate allocation");
    require(X509_set_version(cert.get(),2)==1 && ASN1_INTEGER_set(X509_get_serialNumber(cert.get()),serial)==1,"certificate version");
    require(X509_gmtime_adj(X509_getm_notBefore(cert.get()),-3600) && X509_gmtime_adj(X509_getm_notAfter(cert.get()),86400),"certificate time");
    require(X509_set_pubkey(cert.get(),key)==1,"certificate public key");
    auto subject=X509_get_subject_name(cert.get());
    require(X509_NAME_add_entry_by_txt(subject,"CN",MBSTRING_ASC,reinterpret_cast<const unsigned char*>(name),-1,-1,0)==1,"certificate name");
    require(X509_set_issuer_name(cert.get(),issuer ? X509_get_subject_name(issuer) : subject)==1,"certificate issuer");
    extension(cert.get(),issuer ? issuer : cert.get(),NID_basic_constraints,ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
    extension(cert.get(),issuer ? issuer : cert.get(),NID_key_usage,ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature");
    extension(cert.get(),issuer ? issuer : cert.get(),NID_subject_key_identifier,"hash");
    extension(cert.get(),issuer ? issuer : cert.get(),NID_authority_key_identifier,"keyid:always");
    if (!ca) {
        extension(cert.get(),issuer,NID_ext_key_usage,server ? "serverAuth" : "clientAuth");
        if (server) extension(cert.get(),issuer,NID_subject_alt_name,"DNS:cr01-bench.local");
    }
    require(X509_sign(cert.get(),signer,pq ? nullptr : EVP_sha256())>0,"certificate signature");
    return cert;
}
inline void save(const std::filesystem::path& path, EVP_PKEY* key, X509* cert) {
    // The caller supplies a newly created TemporaryDirectory; fixed filenames only.
    require(!std::filesystem::exists(path),"refusing certificate/key overwrite");
#ifdef _WIN32
    int fd=_wopen(path.c_str(),_O_WRONLY|_O_CREAT|_O_EXCL|_O_BINARY|_O_NOINHERIT,_S_IREAD|_S_IWRITE);
#else
    int fd=::open(path.c_str(),O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
#endif
    require(fd>=0,"exclusive temporary credential creation");
#ifdef _WIN32
    FILE* file=_fdopen(fd,"wb"); if (!file) _close(fd);
#else
    FILE* file=fdopen(fd,"wb"); if (!file) ::close(fd);
#endif
    require(file,"credential stream");
    bool okay=key ? PEM_write_PrivateKey(file,key,nullptr,nullptr,0,nullptr,nullptr)==1 : PEM_write_X509(file,cert)==1;
    int flushed=fflush(file),closed=fclose(file); require(okay && !flushed && !closed,"credential write");
}
inline void provision(const std::filesystem::path& dir, bool pq) {
    std::filesystem::create_directory(dir);
    auto root=identity(pq),client=identity(pq),server=identity(pq);
    auto ca=certificate(root.get(),"CR01 diagnostic temporary CA",1,nullptr,root.get(),pq,true,false);
    auto cc=certificate(client.get(),"CR01 diagnostic client",2,ca.get(),root.get(),pq,false,false);
    auto sc=certificate(server.get(),"cr01-bench.local",3,ca.get(),root.get(),pq,false,true);
    save(dir/"ca.pem",nullptr,ca.get()); save(dir/"client.pem",nullptr,cc.get()); save(dir/"server.pem",nullptr,sc.get());
    save(dir/"client.key",client.get(),nullptr); save(dir/"server.key",server.get(),nullptr);
}
inline Certificate load_certificate(const std::filesystem::path& path) {
    std::unique_ptr<BIO,decltype(&BIO_free)> bio(BIO_new_file(path.string().c_str(),"rb"),BIO_free);
    Certificate cert(bio ? PEM_read_bio_X509(bio.get(),nullptr,nullptr,nullptr) : nullptr,X509_free);
    require(bool(cert),"certificate load"); return cert;
}
inline std::string group(const std::string& profile) { return profile=="tls-classical" ? "X25519" : "X25519MLKEM768"; }
inline std::string signature(const std::string& profile) { return profile=="tls-pq" ? "mldsa65" : "ecdsa_secp256r1_sha256"; }
inline Context context(const std::filesystem::path& dir, const std::string& profile, bool server,
                       bool trust=true, bool own_certificate=true) {
    Context ctx(SSL_CTX_new(TLS_method()),SSL_CTX_free); require(bool(ctx),"SSL context");
    require(SSL_CTX_set_min_proto_version(ctx.get(),TLS1_3_VERSION)==1 && SSL_CTX_set_max_proto_version(ctx.get(),TLS1_3_VERSION)==1,"TLS 1.3 only");
    require(SSL_CTX_set_ciphersuites(ctx.get(),"TLS_AES_256_GCM_SHA384")==1,"TLS cipher");
    require(SSL_CTX_set1_groups_list(ctx.get(),group(profile).c_str())==1,"TLS group unavailable");
    require(SSL_CTX_set1_sigalgs_list(ctx.get(),signature(profile).c_str())==1,"TLS signature unavailable");
    SSL_CTX_set_verify(ctx.get(),SSL_VERIFY_PEER|(server ? SSL_VERIFY_FAIL_IF_NO_PEER_CERT : 0),nullptr);
    SSL_CTX_set_verify_depth(ctx.get(),2);
    require(X509_VERIFY_PARAM_set_flags(SSL_CTX_get0_param(ctx.get()),X509_V_FLAG_X509_STRICT)==1,"strict X509 validation");
    SSL_CTX_set_session_cache_mode(ctx.get(),SSL_SESS_CACHE_OFF);
    SSL_CTX_set_mode(ctx.get(),SSL_MODE_NO_AUTO_CHAIN); // Root is pretrusted, not sent.
    require(SSL_CTX_clear_chain_certs(ctx.get())==1,"TLS leaf-only transmitted chain");
    SSL_CTX_set_options(ctx.get(),SSL_OP_NO_TICKET|SSL_OP_NO_COMPRESSION);
    require(SSL_CTX_set_num_tickets(ctx.get(),0)==1 && SSL_CTX_set_max_early_data(ctx.get(),0)==1,"no early data/tickets");
    if (trust) require(SSL_CTX_load_verify_locations(ctx.get(),(dir/"ca.pem").string().c_str(),nullptr)==1,"CA load");
    auto role=server ? "server" : "client";
    if (own_certificate) {
        require(SSL_CTX_use_certificate_file(ctx.get(),(dir/(std::string(role)+".pem")).string().c_str(),SSL_FILETYPE_PEM)==1,"TLS certificate load");
        require(SSL_CTX_use_PrivateKey_file(ctx.get(),(dir/(std::string(role)+".key")).string().c_str(),SSL_FILETYPE_PEM)==1,"TLS private key load");
        require(SSL_CTX_check_private_key(ctx.get())==1,"TLS key/cert match");
    }
    return ctx;
}
struct TlsConfig {
    Context client,server;
    Certificate expected_client,expected_server;
    std::string profile;
    TlsConfig(const std::filesystem::path& dir,const std::string& selected,bool trust=true,bool client_cert=true)
      : client(context(dir,selected,false,trust,client_cert)),server(context(dir,selected,true)),
        expected_client(load_certificate(dir/"client.pem")),expected_server(load_certificate(dir/"server.pem")),profile(selected) {}
};
class Tls {
    Connection ssl_;
    X509* expected_;
    std::string profile_;
    bool validated_=false;
    Bytes drain() {
        auto out=SSL_get_wbio(ssl_.get()); auto available=BIO_ctrl_pending(out);
        require(available<=cr01::binary::kMaxFrame,"TLS diagnostic output bound");
        Bytes value(available);
        if (available) require(BIO_read(out,value.data(),static_cast<int>(available))==static_cast<int>(available),"TLS BIO drain");
        return value;
    }
    void feed(const Bytes& value) {
        require(value.size()<=cr01::binary::kMaxFrame,"TLS input bound");
        if (!value.empty()) require(BIO_write(SSL_get_rbio(ssl_.get()),value.data(),static_cast<int>(value.size()))==static_cast<int>(value.size()),"TLS BIO feed");
    }
    void validate() {
        require(SSL_get_verify_result(ssl_.get())==X509_V_OK,"TLS peer chain invalid");
        Certificate peer(SSL_get1_peer_certificate(ssl_.get()),X509_free);
        require(peer && X509_cmp(peer.get(),expected_)==0,"TLS leaf pin mismatch");
        auto chain=SSL_get_peer_cert_chain(ssl_.get());
        int sent=(chain ? sk_X509_num(chain) : 0)+(SSL_is_server(ssl_.get())?1:0);
        require(sent==1,"TLS must not send trusted root certificate");
        require(sk_X509_num(SSL_get0_verified_chain(ssl_.get()))==2,"TLS verified chain must include trusted root");
        require(SSL_version(ssl_.get())==TLS1_3_VERSION && !SSL_session_reused(ssl_.get()),"TLS version/resumption mismatch");
        require(std::string(SSL_get_cipher_name(ssl_.get()))=="TLS_AES_256_GCM_SHA384","TLS cipher mismatch");
        const char* negotiated=SSL_get0_group_name(ssl_.get());
        require(negotiated && OPENSSL_strcasecmp(negotiated,group(profile_).c_str())==0,"TLS group fallback");
        const char* sig=nullptr;
        require(SSL_get0_peer_signature_name(ssl_.get(),&sig)==1 && sig
                && OPENSSL_strcasecmp(sig,signature(profile_).c_str())==0,"TLS signature fallback");
        validated_=true;
    }
public:
    Tls(SSL_CTX* ctx,bool server,X509* expected,const std::string& profile,bool wrong_host=false)
      : ssl_(SSL_new(ctx),SSL_free),expected_(expected),profile_(profile) {
        require(bool(ssl_),"SSL allocation");
        auto input=BIO_new(BIO_s_mem()),output=BIO_new(BIO_s_mem());
        if (!input || !output) { BIO_free(input); BIO_free(output); throw std::runtime_error("TLS BIO allocation"); }
        BIO_set_mem_eof_return(input,-1); BIO_set_mem_eof_return(output,-1);
        SSL_set_bio(ssl_.get(),input,output);
        if (server) SSL_set_accept_state(ssl_.get());
        else {
            SSL_set_connect_state(ssl_.get());
            require(SSL_set_tlsext_host_name(ssl_.get(),"cr01-bench.local")==1
                    && SSL_set1_host(ssl_.get(),wrong_host ? "wrong.invalid" : "cr01-bench.local")==1,"TLS hostname setup");
        }
    }
    bool done() const { return validated_; }
    Bytes step(const Bytes& incoming) {
        require(!validated_,"TLS already established"); feed(incoming);
        int result=SSL_do_handshake(ssl_.get());
        if (result==1) validate();
        else { int error=SSL_get_error(ssl_.get(),result); require(error==SSL_ERROR_WANT_READ,"TLS handshake rejected"); }
        return drain();
    }
    Bytes send(const Bytes& data) {
        require(validated_ && !data.empty(),"TLS diagnostic record state");
        std::size_t written=0; require(SSL_write_ex(ssl_.get(),data.data(),data.size(),&written)==1 && written==data.size(),"TLS write");
        return drain();
    }
    Bytes receive(const Bytes& frame) {
        require(validated_,"TLS unconfirmed"); feed(frame);
        Bytes data; data.reserve(frame.size()); std::array<unsigned char,16384> block{};
        for (unsigned n=0;n<1024;++n) {
            std::size_t got=0; int result=SSL_read_ex(ssl_.get(),block.data(),block.size(),&got);
            if (result==1) { data.insert(data.end(),block.begin(),block.begin()+got); continue; }
            require(SSL_get_error(ssl_.get(),result)==SSL_ERROR_WANT_READ,"TLS authentication/read rejected");
            require(!data.empty() && BIO_ctrl_pending(SSL_get_rbio(ssl_.get()))==0,"TLS incomplete diagnostic transfer");
            return data;
        }
        throw std::runtime_error("TLS read bound");
    }
    std::string details() const {
        const char* sig=nullptr; SSL_get0_peer_signature_name(ssl_.get(),&sig);
        return std::string("{\"version\":\"")+SSL_get_version(ssl_.get())+"\",\"cipher\":\""+SSL_get_cipher_name(ssl_.get())+
          "\",\"group\":\""+SSL_get0_group_name(ssl_.get())+"\",\"peer_signature\":\""+(sig?sig:"")+
          "\",\"certificate_verified\":true,\"exact_leaf_pinned\":true,\"hostname_verified_on_client\":true,\"transmitted_peer_certificates\":1,\"verified_chain_certificates\":2,\"root_transmitted\":false,\"resumed\":false}";
    }
};
struct TlsPair {
    Tls i,r;
    explicit TlsPair(TlsConfig& cfg,bool wrong_host=false)
      : i(cfg.client.get(),false,cfg.expected_server.get(),cfg.profile,wrong_host),
        r(cfg.server.get(),true,cfg.expected_client.get(),cfg.profile) {}
    std::size_t handshake() {
        auto flight=i.step({}); std::size_t total=flight.size();
        for (unsigned n=0;n<16;++n) {
            if (!r.done()) { flight=r.step(flight); total+=flight.size(); }
            if (!i.done()) { flight=i.step(flight); total+=flight.size(); }
            if (i.done() && r.done()) return total;
        }
        throw std::runtime_error("TLS handshake iteration bound");
    }
};
struct CrPair {
    Endpoint i,r;
    CrPair(EVP_PKEY* a,EVP_PKEY* b)
      : i("initiator",retained(a),public_bytes(b,1952),bytes("matched-tls-comparison"),1),
        r("responder",retained(b),public_bytes(a,1952),bytes("matched-tls-comparison"),1) {}
    std::size_t handshake() {
        auto a=i.start(),b=r.respond(a),c=i.finish(b),d=r.accept(c); i.confirm(d);
        require(i.session_id()==r.session_id(),"CR01 session mismatch"); return a.size()+b.size()+c.size()+d.size();
    }
};
class Aes {
    Bytes send_key_,receive_key_;
    bool reuse_;
    std::uint64_t sequence_=1;
    std::unique_ptr<EVP_CIPHER_CTX,decltype(&EVP_CIPHER_CTX_free)> enc_{EVP_CIPHER_CTX_new(),EVP_CIPHER_CTX_free},
        dec_{EVP_CIPHER_CTX_new(),EVP_CIPHER_CTX_free};
public:
    Aes(Bytes send,Bytes receive,bool reuse) : send_key_(std::move(send)),receive_key_(std::move(receive)),reuse_(reuse) {
        require(enc_ && dec_ && send_key_.size()==32 && receive_key_.size()==32,"AES setup");
        require(EVP_EncryptInit_ex(enc_.get(),EVP_aes_256_gcm(),nullptr,send_key_.data(),nullptr)==1 &&
                EVP_DecryptInit_ex(dec_.get(),EVP_aes_256_gcm(),nullptr,receive_key_.data(),nullptr)==1,"AES key setup");
    }
    ~Aes() { wipe(send_key_); wipe(receive_key_); }
    Bytes send(const Bytes& data) {
        require(sequence_>0,"AES nonce exhaustion"); Bytes iv=cr01::v2::nonce(sequence_++),ct,tag;
        if (!reuse_) { auto pair=cr01::record::aes_gcm_encrypt(send_key_,iv,data,{}); ct=std::move(pair.first); tag=std::move(pair.second); }
        else {
            require(EVP_EncryptInit_ex(enc_.get(),nullptr,nullptr,nullptr,iv.data())==1,"AES reset");
            ct.resize(data.size()+16); int n=0,tail=0;
            require(EVP_EncryptUpdate(enc_.get(),ct.data(),&n,data.data(),static_cast<int>(data.size()))==1 &&
                    EVP_EncryptFinal_ex(enc_.get(),ct.data()+n,&tail)==1,"AES encrypt");
            ct.resize(n+tail); tag.resize(16); require(EVP_CIPHER_CTX_ctrl(enc_.get(),EVP_CTRL_GCM_GET_TAG,16,tag.data())==1,"AES tag");
        }
        Bytes result; result.reserve(iv.size()+ct.size()+tag.size());
        cr01::record::append(result,iv); cr01::record::append(result,ct); cr01::record::append(result,tag); return result;
    }
    Bytes receive(const Bytes& frame) {
        require(frame.size()>=28 && frame.size()<=cr01::binary::kMaxFrame,"AES frame");
        Bytes iv(frame.begin(),frame.begin()+12),ct(frame.begin()+12,frame.end()-16),tag(frame.end()-16,frame.end());
        if (!reuse_) return cr01::record::aes_gcm_decrypt(receive_key_,iv,ct,tag,{});
        Bytes data(ct.size()+16); int n=0,tail=0;
        require(EVP_DecryptInit_ex(dec_.get(),nullptr,nullptr,nullptr,iv.data())==1 &&
                EVP_DecryptUpdate(dec_.get(),data.data(),&n,ct.data(),static_cast<int>(ct.size()))==1 &&
                EVP_CIPHER_CTX_ctrl(dec_.get(),EVP_CTRL_GCM_SET_TAG,16,tag.data())==1 &&
                EVP_DecryptFinal_ex(dec_.get(),data.data()+n,&tail)==1,"AES tag rejected");
        data.resize(n+tail); return data;
    }
};
} // namespace compare

