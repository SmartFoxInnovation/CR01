#pragma once
// Plaintext research identities. Protected parents and trusted host are required.
#include "channel_v2_secret.hpp"
#include <cstdio>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <vector>
#ifdef _WIN32
#include <aclapi.h>
#include <io.h>
#include <fcntl.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#endif

namespace cr01::identity {
[[noreturn]] inline void fail() { throw std::invalid_argument("identity file rejected"); }
struct CloseFile { void operator()(FILE* file) const noexcept { if (file) fclose(file); } };
using File = std::unique_ptr<FILE, CloseFile>;

#ifdef _WIN32
struct Handle {
    HANDLE value;
    explicit Handle(HANDLE handle) : value(handle) { if (value == INVALID_HANDLE_VALUE || !value) fail(); }
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE take() { return std::exchange(value, nullptr); }
};
class Principals {
    std::vector<unsigned char> token_;
    unsigned char system_[SECURITY_MAX_SID_SIZE]{}, admins_[SECURITY_MAX_SID_SIZE]{};
public:
    Principals() {
        HANDLE raw = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) fail();
        Handle token(raw);
        DWORD size = 0;
        GetTokenInformation(token.value, TokenUser, nullptr, 0, &size);
        if (!size || size > 65536) fail();
        token_.resize(size);
        if (!GetTokenInformation(token.value, TokenUser, token_.data(), size, &size)) fail();
        DWORD length = sizeof(system_);
        if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, system_, &length)) fail();
        length = sizeof(admins_);
        if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admins_, &length)) fail();
    }
    PSID user() const { return reinterpret_cast<const TOKEN_USER*>(token_.data())->User.Sid; }
    PSID system() { return system_; }
    bool allowed(PSID sid) {
        return IsValidSid(sid) && (EqualSid(sid, user()) || EqualSid(sid, system_) || EqualSid(sid, admins_));
    }
};
inline void check_access(HANDLE handle, bool private_file) {
    PSID owner = nullptr; PACL acl = nullptr; PSECURITY_DESCRIPTOR raw = nullptr;
    if (GetSecurityInfo(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                        &owner, nullptr, &acl, nullptr, &raw) != ERROR_SUCCESS) fail();
    const auto free_local = [](void* value) { LocalFree(value); };
    std::unique_ptr<void, decltype(free_local)> descriptor(raw, free_local);
    Principals principals;
    if (!owner || (private_file ? !EqualSid(owner, principals.user()) : !principals.allowed(owner))
        || !acl || !IsValidAcl(acl)) fail();
    for (DWORD index = 0; index < acl->AceCount; ++index) {
        void* raw_ace = nullptr;
        if (!GetAce(acl, index, &raw_ace)) fail();
        const auto* header = static_cast<ACE_HEADER*>(raw_ace);
        if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) fail();
        auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw_ace);
        constexpr DWORD mutable_access = GENERIC_ALL | GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA
            | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE | WRITE_DAC | WRITE_OWNER;
        if (!principals.allowed(&ace->SidStart) && (private_file || (ace->Mask & mutable_access))) fail();
    }
}
template<class Buffer> Buffer read(const std::filesystem::path& path, std::size_t maximum, bool private_file, bool trust_file = true) {
    Handle input(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    BY_HANDLE_FILE_INFORMATION info{};
    if (GetFileType(input.value) != FILE_TYPE_DISK || !GetFileInformationByHandle(input.value, &info)
        || (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) fail();
    if (private_file && info.nNumberOfLinks != 1) fail();
    const auto size = (std::uint64_t(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
    if (!size || size > maximum || size > MAXDWORD) fail();
    if (private_file || trust_file) check_access(input.value, private_file);
    Buffer value(static_cast<std::size_t>(size));
    DWORD received = 0;
    if (!ReadFile(input.value, value.data(), static_cast<DWORD>(size), &received, nullptr) || received != size) fail();
    return value;
}
inline File create(const std::filesystem::path& path) {
    Principals principals;
    EXPLICIT_ACCESSW entries[2]{};
    for (auto& entry : entries) {
        entry.grfAccessPermissions = FILE_ALL_ACCESS;
        entry.grfAccessMode = SET_ACCESS;
        entry.grfInheritance = NO_INHERITANCE;
        entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        entry.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
    }
    entries[0].Trustee.ptstrName = static_cast<LPWSTR>(principals.user());
    entries[1].Trustee.ptstrName = static_cast<LPWSTR>(principals.system());
    PACL acl = nullptr;
    if (SetEntriesInAclW(2, entries, nullptr, &acl) != ERROR_SUCCESS) fail();
    const auto free_local = [](void* value) { LocalFree(value); };
    std::unique_ptr<void, decltype(free_local)> acl_owner(acl, free_local);
    SECURITY_DESCRIPTOR descriptor{};
    if (!InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION)
        || !SetSecurityDescriptorOwner(&descriptor, principals.user(), FALSE)
        || !SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE)
        || !SetSecurityDescriptorControl(&descriptor, SE_DACL_PROTECTED, SE_DACL_PROTECTED)) fail();
    SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES), &descriptor, FALSE};
    Handle output(CreateFileW(path.c_str(), GENERIC_WRITE | READ_CONTROL, 0, &attributes, CREATE_NEW,
                              FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
    check_access(output.value, true);
    const int fd = _open_osfhandle(reinterpret_cast<intptr_t>(output.value), _O_WRONLY | _O_BINARY | _O_NOINHERIT);
    if (fd < 0) fail();
    output.take(); // fd owns the exact newly created handle from here.
    FILE* file = _fdopen(fd, "wb");
    if (!file) { _close(fd); fail(); }
    return File(file);
}
#else
struct Descriptor {
    int value;
    explicit Descriptor(int fd) : value(fd) { if (fd < 0) fail(); }
    ~Descriptor() { if (value >= 0) ::close(value); }
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    int take() { return std::exchange(value, -1); }
};
inline void check_private(const struct stat& info) {
    if (info.st_uid != geteuid() || (info.st_mode & 0077) || !(info.st_mode & S_IRUSR) || info.st_nlink != 1) fail();
}
template<class Buffer> Buffer read(const std::filesystem::path& path, std::size_t maximum, bool private_file, bool trust_file = true) {
    Descriptor input(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    struct stat before{};
    if (fstat(input.value, &before) != 0 || !S_ISREG(before.st_mode) || before.st_size <= 0
        || static_cast<std::uint64_t>(before.st_size) > maximum) fail();
    if (private_file) check_private(before);
    else if (trust_file && ((before.st_uid != geteuid() && before.st_uid != 0) || (before.st_mode & 0022))) fail();
    Buffer value(static_cast<std::size_t>(before.st_size));
    std::size_t offset = 0;
    while (offset < value.size()) {
        const auto n = ::read(input.value, value.data() + offset, value.size() - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) fail();
        offset += static_cast<std::size_t>(n);
    }
    struct stat after{};
    if (fstat(input.value, &after) != 0 || after.st_size != before.st_size
        || after.st_mtim.tv_sec != before.st_mtim.tv_sec || after.st_mtim.tv_nsec != before.st_mtim.tv_nsec
        || after.st_ctim.tv_sec != before.st_ctim.tv_sec || after.st_ctim.tv_nsec != before.st_ctim.tv_nsec) fail();
    if (private_file) check_private(after);
    else if (trust_file && ((after.st_uid != geteuid() && after.st_uid != 0) || (after.st_mode & 0022))) fail();
    return value;
}
inline File create(const std::filesystem::path& path) {
    Descriptor output(::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
    if (fchmod(output.value, 0600) != 0) fail();
    struct stat info{};
    if (fstat(output.value, &info) != 0 || !S_ISREG(info.st_mode)) fail();
    check_private(info);
    FILE* file = fdopen(output.value, "wb");
    if (!file) fail();
    output.take();
    return File(file);
}
#endif
inline memory::Secret read_private(const std::filesystem::path& path) {
    return read<memory::Secret>(path, 65536, true);
}
} // namespace cr01::identity
