#pragma once
// Consumed ciphertext storage, exposed read-only only after authentication.
#include "crypto.hpp"
#include <span>
#include <utility>

namespace cr01::v2 {
class RecordCipher;
class AuthenticatedRecord {
#ifdef CR01_CHANNEL_TESTING
    friend struct PlaintextTestAccess;
    inline static void (*after_wipe_)(std::span<const unsigned char>) noexcept = nullptr;
#endif
    static void wipe_storage(record::Bytes& storage) noexcept {
        if(storage.empty()) return;
        OPENSSL_cleanse(storage.data(),storage.size());
#ifdef CR01_CHANNEL_TESTING
        if (after_wipe_) after_wipe_(storage); // Observe live cleansed objects, never freed memory.
#endif
    }
    record::Bytes storage_;
    std::size_t offset_,size_;
    AuthenticatedRecord(record::Bytes storage,std::size_t offset,std::size_t size)
        :storage_(std::move(storage)),offset_(offset),size_(size) {}
    friend AuthenticatedRecord open_owned(RecordCipher&,const record::Bytes&,unsigned,record::Bytes);
public:
    ~AuthenticatedRecord() { wipe_storage(storage_); }
    AuthenticatedRecord(const AuthenticatedRecord&) = delete;
    AuthenticatedRecord& operator=(const AuthenticatedRecord&) = delete;
    AuthenticatedRecord(AuthenticatedRecord&& other) noexcept
        : storage_(std::move(other.storage_)),offset_(std::exchange(other.offset_,0)),size_(std::exchange(other.size_,0)) {}
    AuthenticatedRecord& operator=(AuthenticatedRecord&& other) noexcept {
        if (this != &other) {
            wipe_storage(storage_);storage_=std::move(other.storage_);
            offset_=std::exchange(other.offset_,0);size_=std::exchange(other.size_,0);
        }
        return *this;
    }
    // A view cannot outlive its owner or be retained across moving that owner.
    std::span<const unsigned char> view() const noexcept {
        return storage_.empty()?std::span<const unsigned char>{}:std::span<const unsigned char>{storage_.data()+offset_,size_};
    }
    // Only zeros leave this route. Transfer capacity back to a transport buffer,
    // never plaintext or resumable traffic state. Existing views are invalidated.
    record::Bytes take_cleansed_storage() noexcept {
        wipe_storage(storage_);offset_=size_=0;
        return std::exchange(storage_,record::Bytes{});
    }
};
} // namespace cr01::v2
