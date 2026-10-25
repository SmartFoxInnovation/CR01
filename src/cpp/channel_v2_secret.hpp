#pragma once
// Only explicitly owned native intermediates are covered, not provider/OS copies.
#include <openssl/crypto.h>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <utility>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <unistd.h>
#endif

namespace cr01::memory {

class Secret {
    unsigned char* data_ = nullptr;
    std::size_t size_ = 0, mapped_ = 0;
    bool locked_ = false;
#ifdef CR01_CHANNEL_TESTING
    friend struct SecretTestAccess;
    inline static unsigned fail_ = 0;
    inline static std::size_t live_ = 0;
    inline static std::size_t allocations_ = 0;
    inline static void (*after_wipe_)(std::span<const unsigned char>) noexcept = nullptr;
#endif
    void release() noexcept {
        if (!data_) return;
        OPENSSL_cleanse(data_, mapped_);
#ifdef CR01_CHANNEL_TESTING
        if (after_wipe_) after_wipe_({data_, mapped_});
        --live_;
#endif
#ifdef _WIN32
        if (locked_) VirtualUnlock(data_, mapped_);
        VirtualFree(data_, 0, MEM_RELEASE);
#else
        if (locked_) munlock(data_, mapped_);
        munmap(data_, mapped_);
#endif
        data_ = nullptr; size_ = mapped_ = 0; locked_ = false;
    }
public:
    Secret() = default;
    explicit Secret(std::size_t size) {
        if (!size || size > 65536) throw std::invalid_argument("secret size rejected");
#ifdef CR01_CHANNEL_TESTING
        if (fail_ == 1) throw std::runtime_error("secret allocation unavailable");
#endif
#ifdef _WIN32
        SYSTEM_INFO info{}; GetSystemInfo(&info);
        const auto page = static_cast<std::size_t>(info.dwPageSize);
#else
        const auto queried = sysconf(_SC_PAGESIZE);
        if (queried <= 0) throw std::runtime_error("secret page size unavailable");
        const auto page = static_cast<std::size_t>(queried);
#endif
        if (!page || page > 65536) throw std::runtime_error("secret page size rejected");
        mapped_ = ((size + page - 1) / page) * page;
#ifdef _WIN32
        data_ = static_cast<unsigned char*>(VirtualAlloc(nullptr, mapped_, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
#else
        void* region = mmap(nullptr, mapped_, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        data_ = region == MAP_FAILED ? nullptr : static_cast<unsigned char*>(region);
#endif
        if (!data_) { mapped_ = 0; throw std::runtime_error("secret allocation unavailable"); }
        size_ = size;
#ifdef CR01_CHANNEL_TESTING
        ++live_;
        ++allocations_;
        if (fail_ == 2) { release(); throw std::runtime_error("secret lock unavailable"); }
#endif
#ifdef _WIN32
        locked_ = VirtualLock(data_, mapped_) != 0;
#else
        locked_ = mlock(data_, mapped_) == 0;
#endif
        if (!locked_) { release(); throw std::runtime_error("secret lock unavailable"); }
#ifndef _WIN32
        if (madvise(data_, mapped_, MADV_DONTDUMP) != 0) {
            release(); throw std::runtime_error("secret dump exclusion unavailable");
        }
#endif
#ifdef CR01_CHANNEL_TESTING
        if (fail_ == 3) { release(); throw std::runtime_error("secret protection unavailable"); }
#endif
    }
    ~Secret() { release(); }
    Secret(const Secret&) = delete;
    Secret& operator=(const Secret&) = delete;
    Secret(Secret&& other) noexcept
        : data_(std::exchange(other.data_, nullptr)), size_(std::exchange(other.size_, 0)),
          mapped_(std::exchange(other.mapped_, 0)), locked_(std::exchange(other.locked_, false)) {}
    Secret& operator=(Secret&& other) noexcept {
        if (this != &other) {
            release(); data_ = std::exchange(other.data_, nullptr); size_ = std::exchange(other.size_, 0);
            mapped_ = std::exchange(other.mapped_, 0); locked_ = std::exchange(other.locked_, false);
        }
        return *this;
    }
    unsigned char* data() noexcept { return data_; }
    const unsigned char* data() const noexcept { return data_; }
    std::size_t size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }
    std::span<const unsigned char> view() const noexcept { return {data_, size_}; }
    void clear() noexcept { release(); }
};

inline void restrict_process_dumps() {
#ifndef _WIN32
    const rlimit limit{0, 0};
    if (setrlimit(RLIMIT_CORE, &limit) != 0 || prctl(PR_SET_DUMPABLE, 0) != 0)
        throw std::runtime_error("process dump restriction unavailable");
#endif
    // Windows WER/admin/hypervisor dumps remain an operator policy, not a claim.
}
} // namespace cr01::memory
