// securelog.cpp - implementation. See securelog.hpp for the design summary.
#include "securelog.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <set>

namespace securelog {

namespace {

constexpr const char* kMagic = "SL1";
constexpr std::size_t kIvLen = 12;
constexpr std::size_t kTagLen = 16;
constexpr std::size_t kHashLen = 32;
constexpr std::size_t kMaxRawMessage = 2048;
constexpr std::size_t kMaxPlain = 8192;          // after escaping
constexpr std::size_t kMaxLineLen = 2 * kMaxPlain + 256;
constexpr std::size_t kMaxFileBytes = 1ull << 30;  // refuse to slurp > 1 GiB

// ------------------------------------------------------------------ small utils
struct Fd {
    int fd;
    explicit Fd(int f) : fd(f) {}
    ~Fd() {
        if (fd >= 0) ::close(fd);
    }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
};

std::string to_hex(const std::uint8_t* d, std::size_t n) {
    static const char* h = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        s.push_back(h[d[i] >> 4]);
        s.push_back(h[d[i] & 15]);
    }
    return s;
}

int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool from_hex(const std::string& s, std::vector<std::uint8_t>& out) {
    if (s.size() % 2 != 0) return false;
    out.clear();
    out.reserve(s.size() / 2);
    for (std::size_t i = 0; i < s.size(); i += 2) {
        int a = hex_val(s[i]), b = hex_val(s[i + 1]);
        if (a < 0 || b < 0) return false;
        out.push_back(static_cast<std::uint8_t>((a << 4) | b));
    }
    return true;
}

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    for (;;) {
        std::size_t p = s.find(delim, start);
        if (p == std::string::npos) {
            parts.push_back(s.substr(start));
            break;
        }
        parts.push_back(s.substr(start, p - start));
        start = p + 1;
    }
    return parts;
}

bool parse_u64(const std::string& s, std::uint64_t& out) {
    if (s.empty() || s.size() > 20) return false;
    std::uint64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        std::uint64_t d = static_cast<std::uint64_t>(c - '0');
        if (v > (UINT64_MAX - d) / 10) return false;
        v = v * 10 + d;
    }
    out = v;
    return true;
}

bool random_bytes(std::uint8_t* buf, std::size_t n) {
    return RAND_bytes(buf, static_cast<int>(n)) == 1;
}

bool sha256(const std::string& data, std::uint8_t out[kHashLen]) {
    unsigned int len = 0;
    return EVP_Digest(data.data(), data.size(), out, &len, EVP_sha256(), nullptr) == 1 &&
           len == kHashLen;
}

std::string utc_now() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

bool valid_timestamp(const std::string& s) {
    // YYYY-MM-DDTHH:MM:SSZ
    if (s.size() != 20) return false;
    for (std::size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (i == 4 || i == 7) {
            if (c != '-') return false;
        } else if (i == 10) {
            if (c != 'T') return false;
        } else if (i == 13 || i == 16) {
            if (c != ':') return false;
        } else if (i == 19) {
            if (c != 'Z') return false;
        } else if (c < '0' || c > '9') {
            return false;
        }
    }
    return true;
}

// ------------------------------------------------------------------- file I/O
bool write_all(int fd, const std::string& data) {
    const char* p = data.data();
    std::size_t left = data.size();
    while (left > 0) {
        ssize_t n = ::write(fd, p, left);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        p += n;
        left -= static_cast<std::size_t>(n);
    }
    return true;
}

bool read_fd_all(int fd, std::string& out) {
    struct stat st{};
    if (fstat(fd, &st) != 0) return false;
    if (st.st_size < 0 || static_cast<std::uint64_t>(st.st_size) > kMaxFileBytes) return false;
    out.assign(static_cast<std::size_t>(st.st_size), '\0');
    std::size_t got = 0;
    while (got < out.size()) {
        ssize_t n = ::pread(fd, &out[got], out.size() - got, static_cast<off_t>(got));
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) break;
        got += static_cast<std::size_t>(n);
    }
    out.resize(got);
    return true;
}

// Opens a secret-bearing file (keys / users). Refuses symlinks, non-regular files
// and anything accessible by group or others.
int open_private(const std::string& path, int flags, Status& st_out) {
    int fd = ::open(path.c_str(), flags | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        st_out = Status::IoError;
        return -1;
    }
    struct stat st{};
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || (st.st_mode & 077) != 0) {
        ::close(fd);
        st_out = Status::KeyError;
        return -1;
    }
    st_out = Status::Ok;
    return fd;
}

// ------------------------------------------------- HMAC, secrets, atomic files
bool hmac256(const Key& key, const std::string& data, Key& out) {
    unsigned int len = 0;
    return HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
                reinterpret_cast<const unsigned char*>(data.data()), data.size(), out.data(),
                &len) != nullptr &&
           len == out.size();
}

// Key holder that wipes itself on destruction.
struct SecretKey {
    Key k{};
    SecretKey() = default;
    SecretKey(const SecretKey&) = delete;
    SecretKey& operator=(const SecretKey&) = delete;
    ~SecretKey() { OPENSSL_cleanse(k.data(), k.size()); }
};

// Write-to-temp, fsync, rename, fsync directory: the file is always either the old
// or the new content, never a torn mix (matters for the evolving key state).
bool atomic_write_private(const std::string& path, const std::string& content) {
    const std::string tmp = path + ".tmp";
    ::unlink(tmp.c_str());
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    bool ok = write_all(fd, content) && fsync(fd) == 0;
    ::close(fd);
    if (!ok || ::rename(tmp.c_str(), path.c_str()) != 0) {
        ::unlink(tmp.c_str());
        return false;
    }
    const std::size_t slash = path.rfind('/');
    const std::string dir = slash == std::string::npos ? "." : path.substr(0, slash);
    int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dfd >= 0) {
        (void)fsync(dfd);
        ::close(dfd);
    }
    return true;
}

// Evolving chain-key state kept on the logging host: only the CURRENT key.
struct ChainState {
    std::uint64_t index = 0;   // sequence number of the next record to write
    std::uint32_t key_id = 0;  // epoch / root key id
    Key ck{};                  // chain key CK[index]
    ChainState() = default;
    ChainState(const ChainState&) = delete;
    ChainState& operator=(const ChainState&) = delete;
    ~ChainState() { OPENSSL_cleanse(ck.data(), ck.size()); }
};

Status load_state(const std::string& path, ChainState& st) {
    Status s;
    int fd = open_private(path, O_RDONLY, s);
    if (fd < 0) return s == Status::IoError ? Status::KeyError : s;
    Fd g(fd);
    std::string c;
    if (!read_fd_all(fd, c)) return Status::KeyError;
    Status r = Status::KeyError;
    if (!c.empty() && c.back() == '\n') {
        auto f = split(c.substr(0, c.size() - 1), ':');
        std::uint64_t idx = 0, kid = 0;
        std::vector<std::uint8_t> raw;
        if (f.size() == 3 && parse_u64(f[0], idx) && idx > 0 && parse_u64(f[1], kid) && kid > 0 &&
            kid <= 0xFFFFFFFFull && from_hex(f[2], raw) && raw.size() == 32) {
            st.index = idx;
            st.key_id = static_cast<std::uint32_t>(kid);
            std::copy(raw.begin(), raw.end(), st.ck.begin());
            r = Status::Ok;
        }
        if (!raw.empty()) OPENSSL_cleanse(raw.data(), raw.size());
    }
    if (!c.empty()) OPENSSL_cleanse(&c[0], c.size());
    return r;
}

Status save_state(const std::string& path, const ChainState& st) {
    std::string c = std::to_string(st.index) + ":" + std::to_string(st.key_id) + ":" +
                    to_hex(st.ck.data(), st.ck.size()) + "\n";
    bool ok = atomic_write_private(path, c);
    OPENSSL_cleanse(&c[0], c.size());
    return ok ? Status::Ok : Status::IoError;
}

// Authenticated head anchor: "seq:hash:mac". mac = HMAC(HMAC(CK[seq], "anchor"), data).
struct Anchor {
    bool present = false;
    std::uint64_t seq = 0;
    std::string hash;
    std::vector<std::uint8_t> mac;
};

std::string anchor_data(std::uint64_t seq, const std::string& hash_hex) {
    return "SL1-ANCHOR|" + std::to_string(seq) + "|" + hash_hex;
}

bool anchor_mac(const Key& ck, std::uint64_t seq, const std::string& hash_hex, Key& out) {
    SecretKey mk;
    return hmac256(ck, "securelog/anchor/v1", mk.k) && hmac256(mk.k, anchor_data(seq, hash_hex), out);
}

Status write_anchor(const std::string& path, std::uint64_t seq, const std::string& hash_hex,
                    const Key& ck) {
    Key mac{};
    if (!anchor_mac(ck, seq, hash_hex, mac)) return Status::CryptoError;
    const std::string c =
        std::to_string(seq) + ":" + hash_hex + ":" + to_hex(mac.data(), mac.size()) + "\n";
    return atomic_write_private(path, c) ? Status::Ok : Status::IoError;
}

// Missing file => present=false. Malformed => FormatError (caller treats as tampering).
Status load_anchor(const std::string& path, Anchor& a) {
    a = Anchor{};
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return errno == ENOENT ? Status::Ok : Status::IoError;
    Fd g(fd);
    struct stat st{};
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || (st.st_mode & 022) != 0)
        return Status::IoError;
    std::string c;
    if (!read_fd_all(fd, c) || c.empty() || c.back() != '\n' || c.size() > 512)
        return Status::FormatError;
    auto f = split(c.substr(0, c.size() - 1), ':');
    std::vector<std::uint8_t> h;
    if (f.size() != 3 || !parse_u64(f[0], a.seq) || a.seq == 0 || f[1].size() != 64 ||
        !from_hex(f[1], h) || f[2].size() != 64 || !from_hex(f[2], a.mac))
        return Status::FormatError;
    a.hash = f[1];
    a.present = true;
    return Status::Ok;
}

// ---------------------------------------------------------------- crypto layer
bool gcm_encrypt(const Key& key, const std::uint8_t* iv, const std::string& aad,
                 const std::string& pt, std::vector<std::uint8_t>& ct,
                 std::uint8_t tag[kTagLen]) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    int len = 0;
    ct.assign(pt.size() + 16, 0);
    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kIvLen), nullptr) != 1)
            break;
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv) != 1) break;
        if (EVP_EncryptUpdate(ctx, nullptr, &len,
                              reinterpret_cast<const unsigned char*>(aad.data()),
                              static_cast<int>(aad.size())) != 1)
            break;
        int total = 0;
        if (EVP_EncryptUpdate(ctx, ct.data(), &len,
                              reinterpret_cast<const unsigned char*>(pt.data()),
                              static_cast<int>(pt.size())) != 1)
            break;
        total = len;
        if (EVP_EncryptFinal_ex(ctx, ct.data() + total, &len) != 1) break;
        total += len;
        if (static_cast<std::size_t>(total) != pt.size()) break;
        ct.resize(pt.size());
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(kTagLen), tag) != 1)
            break;
        ok = true;
    } while (false);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool gcm_decrypt(const Key& key, const std::uint8_t* iv, const std::string& aad,
                 const std::vector<std::uint8_t>& ct, const std::uint8_t* tag,
                 std::string& pt) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    int len = 0;
    std::vector<std::uint8_t> buf(ct.size() + 16, 0);
    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kIvLen), nullptr) != 1)
            break;
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv) != 1) break;
        if (EVP_DecryptUpdate(ctx, nullptr, &len,
                              reinterpret_cast<const unsigned char*>(aad.data()),
                              static_cast<int>(aad.size())) != 1)
            break;
        int total = 0;
        if (EVP_DecryptUpdate(ctx, buf.data(), &len, ct.data(), static_cast<int>(ct.size())) != 1)
            break;
        total = len;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(kTagLen),
                                const_cast<std::uint8_t*>(tag)) != 1)
            break;
        // Final returns <= 0 when the authentication tag does not match.
        if (EVP_DecryptFinal_ex(ctx, buf.data() + total, &len) <= 0) break;
        total += len;
        pt.assign(reinterpret_cast<const char*>(buf.data()), static_cast<std::size_t>(total));
        ok = true;
    } while (false);
    OPENSSL_cleanse(buf.data(), buf.size());
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// -------------------------------------------------------------------- records
struct Record {
    std::uint64_t seq = 0;
    std::string ts;
    std::string sev;
    std::string actor;
    std::uint32_t key_id = 0;
    std::vector<std::uint8_t> iv;
    std::vector<std::uint8_t> ct;
    std::vector<std::uint8_t> tag;
    std::string prev_hex;
    std::string aad;  // authenticated header
};

std::string make_aad(std::uint64_t seq, const std::string& ts, const std::string& sev,
                     const std::string& actor, std::uint32_t key_id,
                     const std::string& prev_hex) {
    return std::string(kMagic) + "|" + std::to_string(seq) + "|" + ts + "|" + sev + "|" + actor +
           "|" + std::to_string(key_id) + "|" + prev_hex;
}

// Strict parser: exactly 10 '|' separated fields with validated shapes and lengths.
bool parse_line(const std::string& line, Record& r) {
    if (line.empty() || line.size() > kMaxLineLen) return false;
    auto f = split(line, '|');
    if (f.size() != 10 || f[0] != kMagic) return false;
    std::uint64_t kid = 0;
    Severity sv;
    if (!parse_u64(f[1], r.seq) || r.seq == 0) return false;
    if (!valid_timestamp(f[2])) return false;
    if (!parse_severity(f[3], sv)) return false;
    if (!is_valid_name(f[4])) return false;
    if (!parse_u64(f[5], kid) || kid == 0 || kid > 0xFFFFFFFFull) return false;
    if (f[6].size() != kIvLen * 2 || !from_hex(f[6], r.iv)) return false;
    if (f[7].size() > kMaxPlain * 2 || !from_hex(f[7], r.ct)) return false;
    if (f[8].size() != kTagLen * 2 || !from_hex(f[8], r.tag)) return false;
    if (f[9].size() != kHashLen * 2) return false;
    std::vector<std::uint8_t> tmp;
    if (!from_hex(f[9], tmp)) return false;
    r.ts = f[2];
    r.sev = f[3];
    r.actor = f[4];
    r.key_id = static_cast<std::uint32_t>(kid);
    r.prev_hex = f[9];
    r.aad = make_aad(r.seq, r.ts, r.sev, r.actor, r.key_id, r.prev_hex);
    return true;
}

const std::string kZeroHash(kHashLen * 2, '0');

// Pre-computed PBKDF2 parameters used so unknown users cost the same as known ones.
const std::uint8_t kDummySalt[16] = {0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
                                     0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a};

bool pbkdf2(const std::string& token, const std::uint8_t* salt, std::size_t salt_len,
            std::uint32_t iters, std::uint8_t out[32]) {
    return PKCS5_PBKDF2_HMAC(token.data(), static_cast<int>(token.size()), salt,
                             static_cast<int>(salt_len), static_cast<int>(iters), EVP_sha256(),
                             32, out) == 1;
}

struct UserRec {
    std::string name;
    Role role = Role::Logger;
    std::uint32_t iters = 0;
    std::vector<std::uint8_t> salt;
    std::vector<std::uint8_t> hash;
};

bool parse_user_line(const std::string& line, UserRec& u) {
    auto f = split(line, ':');
    if (f.size() != 5) return false;
    std::uint64_t it = 0;
    if (!is_valid_name(f[0]) || !parse_role(f[1], u.role)) return false;
    if (!parse_u64(f[2], it) || it == 0 || it > 10000000) return false;
    if (!from_hex(f[3], u.salt) || u.salt.size() != 16) return false;
    if (!from_hex(f[4], u.hash) || u.hash.size() != 32) return false;
    u.name = f[0];
    u.iters = static_cast<std::uint32_t>(it);
    return true;
}

}  // namespace

// ============================================================ public free helpers
const char* to_string(Status s) {
    switch (s) {
        case Status::Ok: return "ok";
        case Status::AuthFailed: return "authentication failed";
        case Status::Denied: return "access denied";
        case Status::InvalidInput: return "invalid input";
        case Status::IoError: return "i/o error";
        case Status::CryptoError: return "cryptographic error";
        case Status::TamperDetected: return "tampering detected";
        case Status::KeyError: return "key error";
        case Status::FormatError: return "log format error";
    }
    return "unknown";
}

const char* to_string(Severity s) {
    switch (s) {
        case Severity::Debug: return "DEBUG";
        case Severity::Info: return "INFO";
        case Severity::Warn: return "WARN";
        case Severity::Error: return "ERROR";
        case Severity::Critical: return "CRITICAL";
    }
    return "INFO";
}

bool parse_severity(const std::string& text, Severity& out) {
    std::string t = text;
    std::transform(t.begin(), t.end(), t.begin(),
                   [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
    static const std::pair<const char*, Severity> tbl[] = {
        {"DEBUG", Severity::Debug}, {"INFO", Severity::Info},         {"WARN", Severity::Warn},
        {"ERROR", Severity::Error}, {"CRITICAL", Severity::Critical}};
    for (const auto& e : tbl) {
        if (t == e.first) {
            out = e.second;
            return true;
        }
    }
    return false;
}

const char* to_string(Role r) {
    switch (r) {
        case Role::Logger: return "logger";
        case Role::Auditor: return "auditor";
        case Role::Admin: return "admin";
    }
    return "logger";
}

const char* to_string(Action a) {
    switch (a) {
        case Action::Write: return "write";
        case Action::Read: return "read";
        case Action::Verify: return "verify";
        case Action::ManageUsers: return "manage_users";
        case Action::RotateKey: return "rotate_key";
    }
    return "unknown";
}

bool parse_role(const std::string& text, Role& out) {
    if (text == "logger") out = Role::Logger;
    else if (text == "auditor") out = Role::Auditor;
    else if (text == "admin") out = Role::Admin;
    else return false;
    return true;
}

bool is_authorized(Role role, Action action) {
    switch (role) {
        case Role::Logger:
            return action == Action::Write;
        case Role::Auditor:
            return action == Action::Read || action == Action::Verify;
        case Role::Admin:
            return action == Action::Verify || action == Action::ManageUsers ||
                   action == Action::RotateKey;
    }
    return false;  // deny by default
}

bool is_valid_name(const std::string& s) {
    if (s.empty() || s.size() > 32) return false;
    for (unsigned char c : s) {
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '_' || c == '-' || c == '.';
        if (!ok) return false;
    }
    return true;
}

// Escapes control characters so a message can never forge extra log lines or
// terminal escape sequences when displayed (log-injection defence).
bool sanitize_message(const std::string& in, std::string& out) {
    if (in.empty() || in.size() > kMaxRawMessage) return false;
    out.clear();
    out.reserve(in.size());
    static const char* h = "0123456789abcdef";
    for (unsigned char c : in) {
        if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (c == '\\') out += "\\\\";
        else if (c < 0x20 || c == 0x7f) {
            out += "\\x";
            out.push_back(h[c >> 4]);
            out.push_back(h[c & 15]);
        } else {
            out.push_back(static_cast<char>(c));
        }
    }
    return out.size() <= kMaxPlain;
}

// ===================================================== forward-secure key schedule
//   CK[first] = HMAC(root, "init" | first_seq)     start of an epoch
//   CK[i+1]   = HMAC(CK[i], "next")                one-way ratchet (old key is erased)
//   EK[i]     = HMAC(CK[i], "enc")                 AES-256-GCM key for record i only
bool derive_start_key(const Key& root, std::uint64_t first_seq, Key& out) {
    return hmac256(root, "securelog/init/v1|" + std::to_string(first_seq), out);
}
bool next_chain_key(const Key& ck, Key& out) { return hmac256(ck, "securelog/next/v1", out); }
bool record_enc_key(const Key& ck, Key& out) { return hmac256(ck, "securelog/enc/v1", out); }

bool decrypt_record_line(const std::string& line, const Key& enc_key, std::string& plain) {
    Record r;
    if (!parse_line(line, r)) return false;
    return gcm_decrypt(enc_key, r.iv.data(), r.aad, r.ct, r.tag.data(), plain);
}

bool parse_checkpoint(const std::string& text, Checkpoint& out) {
    auto f = split(text, ':');
    std::vector<std::uint8_t> tmp;
    if (f.size() != 2 || !parse_u64(f[0], out.seq) || out.seq == 0 || f[1].size() != 64 ||
        !from_hex(f[1], tmp))
        return false;
    out.hash = f[1];
    std::transform(out.hash.begin(), out.hash.end(), out.hash.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return true;
}
std::string to_string(const Checkpoint& c) { return std::to_string(c.seq) + ":" + c.hash; }

// =================================================================== KeyRing
KeyRing::~KeyRing() {
    for (auto& kv : keys_) OPENSSL_cleanse(kv.second.data(), kv.second.size());
}

const Key* KeyRing::get(std::uint32_t id) const {
    auto it = keys_.find(id);
    return it == keys_.end() ? nullptr : &it->second;
}

static Status parse_key_file(const std::string& content, std::map<std::uint32_t, Key>& keys,
                             std::uint32_t& active) {
    keys.clear();
    active = 0;
    std::size_t pos = 0;
    while (pos < content.size()) {
        std::size_t nl = content.find('\n', pos);
        if (nl == std::string::npos) return Status::KeyError;  // must be newline terminated
        std::string line = content.substr(pos, nl - pos);
        pos = nl + 1;
        if (line.empty()) continue;
        auto f = split(line, ':');
        std::uint64_t id = 0;
        std::vector<std::uint8_t> raw;
        if (f.size() != 2 || !parse_u64(f[0], id) || id == 0 || id > 0xFFFFFFFFull ||
            !from_hex(f[1], raw) || raw.size() != 32 || keys.count(static_cast<std::uint32_t>(id))) {
            if (!raw.empty()) OPENSSL_cleanse(raw.data(), raw.size());
            return Status::KeyError;
        }
        Key k{};
        std::copy(raw.begin(), raw.end(), k.begin());
        OPENSSL_cleanse(raw.data(), raw.size());
        keys[static_cast<std::uint32_t>(id)] = k;
        OPENSSL_cleanse(k.data(), k.size());
        active = std::max(active, static_cast<std::uint32_t>(id));
    }
    return keys.empty() ? Status::KeyError : Status::Ok;
}

Status KeyRing::load(const std::string& path) {
    Status st;
    int fd = open_private(path, O_RDONLY, st);
    if (fd < 0) return st == Status::IoError ? Status::KeyError : st;
    Fd g(fd);
    std::string content;
    if (!read_fd_all(fd, content)) return Status::KeyError;
    Status r = parse_key_file(content, keys_, active_);
    OPENSSL_cleanse(&content[0], content.size());
    return r;
}

Status KeyRing::create(const std::string& path) {
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return Status::IoError;
    Fd g(fd);
    Key k{};
    if (!random_bytes(k.data(), k.size())) return Status::CryptoError;
    std::string line = "1:" + to_hex(k.data(), k.size()) + "\n";
    OPENSSL_cleanse(k.data(), k.size());
    bool ok = write_all(fd, line) && fsync(fd) == 0;
    OPENSSL_cleanse(&line[0], line.size());
    return ok ? Status::Ok : Status::IoError;
}

Status KeyRing::rotate(const std::string& path, std::uint32_t& new_id) {
    Status st;
    int fd = open_private(path, O_RDWR | O_APPEND, st);
    if (fd < 0) return st == Status::IoError ? Status::KeyError : st;
    Fd g(fd);
    if (flock(fd, LOCK_EX) != 0) return Status::IoError;
    std::string content;
    if (!read_fd_all(fd, content)) return Status::KeyError;
    std::map<std::uint32_t, Key> keys;
    std::uint32_t active = 0;
    Status r = parse_key_file(content, keys, active);
    OPENSSL_cleanse(&content[0], content.size());
    for (auto& kv : keys) OPENSSL_cleanse(kv.second.data(), kv.second.size());
    if (r != Status::Ok) return r;
    if (active == 0xFFFFFFFFu) return Status::KeyError;
    Key k{};
    if (!random_bytes(k.data(), k.size())) return Status::CryptoError;
    std::string line = std::to_string(active + 1) + ":" + to_hex(k.data(), k.size()) + "\n";
    OPENSSL_cleanse(k.data(), k.size());
    bool ok = write_all(fd, line) && fsync(fd) == 0;
    OPENSSL_cleanse(&line[0], line.size());
    if (!ok) return Status::IoError;
    new_id = active + 1;
    return Status::Ok;
}

// ============================================================== AccessControl
AccessControl::AccessControl(std::string users_path, std::uint32_t pbkdf2_iters)
    : path_(std::move(users_path)), iters_(pbkdf2_iters) {}

Status AccessControl::make_line(const std::string& name, Role role, std::string& token_out,
                                std::string& line) const {
    if (!is_valid_name(name) || iters_ == 0) return Status::InvalidInput;
    std::uint8_t tok[32], salt[16], hash[32];
    if (!random_bytes(tok, sizeof tok) || !random_bytes(salt, sizeof salt)) return Status::CryptoError;
    std::string token = to_hex(tok, sizeof tok);
    OPENSSL_cleanse(tok, sizeof tok);
    if (!pbkdf2(token, salt, sizeof salt, iters_, hash)) return Status::CryptoError;
    line = name + ":" + to_string(role) + ":" + std::to_string(iters_) + ":" +
           to_hex(salt, sizeof salt) + ":" + to_hex(hash, sizeof hash) + "\n";
    token_out = token;
    OPENSSL_cleanse(&token[0], token.size());
    return Status::Ok;
}

Status AccessControl::create_with_admin(const std::string& name, std::string& token_out) {
    std::string line;
    Status s = make_line(name, Role::Admin, token_out, line);
    if (s != Status::Ok) return s;
    int fd = ::open(path_.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return Status::IoError;
    Fd g(fd);
    return (write_all(fd, line) && fsync(fd) == 0) ? Status::Ok : Status::IoError;
}

Status AccessControl::add_user(const std::string& name, Role role, std::string& token_out) {
    Status st;
    int fd = open_private(path_, O_RDWR | O_APPEND, st);
    if (fd < 0) return st;
    Fd g(fd);
    if (flock(fd, LOCK_EX) != 0) return Status::IoError;
    std::string content;
    if (!read_fd_all(fd, content)) return Status::IoError;
    for (const auto& l : split(content, '\n')) {
        if (l.empty()) continue;
        UserRec u;
        if (!parse_user_line(l, u)) return Status::FormatError;
        if (u.name == name) return Status::InvalidInput;  // already exists
    }
    std::string line;
    Status s = make_line(name, role, token_out, line);
    if (s != Status::Ok) return s;
    return (write_all(fd, line) && fsync(fd) == 0) ? Status::Ok : Status::IoError;
}

Status AccessControl::authenticate(const Credentials& c, Identity& id) const {
    Status st;
    int fd = open_private(path_, O_RDONLY, st);
    if (fd < 0) return st;
    Fd g(fd);
    std::string content;
    if (!read_fd_all(fd, content)) return Status::IoError;

    UserRec found;
    bool have = false;
    for (const auto& l : split(content, '\n')) {
        if (l.empty()) continue;
        UserRec u;
        if (!parse_user_line(l, u)) return Status::FormatError;  // fail closed
        if (!have && u.name == c.user) {
            found = u;
            have = true;
        }
    }
    // Always run PBKDF2 (dummy parameters for unknown users) so timing does not
    // reveal whether a user name exists.
    std::uint8_t out[32];
    const std::uint8_t* salt = have ? found.salt.data() : kDummySalt;
    std::uint32_t iters = have ? found.iters : (iters_ ? iters_ : 1000);
    bool token_ok = !c.token.empty() && c.token.size() <= 256;
    if (!pbkdf2(c.token, salt, 16, iters, out)) return Status::CryptoError;
    std::uint8_t expect[32] = {0};
    if (have) std::memcpy(expect, found.hash.data(), 32);
    bool match = CRYPTO_memcmp(out, expect, 32) == 0;
    OPENSSL_cleanse(out, sizeof out);
    if (!(match && have && token_ok && is_valid_name(c.user))) return Status::AuthFailed;
    id.user = found.name;
    id.role = found.role;
    return Status::Ok;
}

// ============================================================== SecureLogger
SecureLogger::SecureLogger(Config cfg)
    : cfg_(std::move(cfg)), ac_(cfg_.dir + "/users.db", cfg_.pbkdf2_iters) {}

std::string SecureLogger::log_path() const { return cfg_.dir + "/securelog.enc"; }
std::string SecureLogger::keys_path() const {
    return cfg_.keys_file.empty() ? cfg_.dir + "/keys.db" : cfg_.keys_file;
}
std::string SecureLogger::state_path() const { return cfg_.dir + "/state.key"; }
std::string SecureLogger::anchor_path() const { return cfg_.dir + "/anchor.mac"; }
std::string SecureLogger::users_path() const { return cfg_.dir + "/users.db"; }

Status SecureLogger::init(const std::string& admin_name, std::string& admin_token_out) {
    if (cfg_.dir.empty() || !is_valid_name(admin_name)) return Status::InvalidInput;
    if (::mkdir(cfg_.dir.c_str(), 0700) != 0 && errno != EEXIST) return Status::IoError;
    KeyRing ring;
    Status s = ring.create(keys_path());  // O_EXCL: refuses to re-initialize
    if (s != Status::Ok) return s;
    s = ring.load(keys_path());
    if (s != Status::Ok) return s;
    const Key* root = ring.get(1);
    if (!root) return Status::KeyError;
    ChainState cs;
    cs.index = 1;
    cs.key_id = 1;
    if (!derive_start_key(*root, 1, cs.ck)) return Status::CryptoError;
    s = save_state(state_path(), cs);
    if (s != Status::Ok) return s;
    return ac_.create_with_admin(admin_name, admin_token_out);
}

namespace {
struct Head {
    std::uint64_t seq = 0;                 // last record's sequence number (0 = empty log)
    std::string hash_hex = kZeroHash;      // SHA-256 of the last record's line
};
}  // namespace

// Reads the last record of the log (cheap: only the tail of the file).
static Status read_head(int fd, const struct stat& st, Head& head) {
    head = Head{};
    if (st.st_size <= 0) return Status::Ok;
    const std::uint64_t size = static_cast<std::uint64_t>(st.st_size);
    const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(size, 2 * kMaxLineLen));
    std::string tail(n, '\0');
    std::size_t got = 0;
    while (got < n) {
        ssize_t r = ::pread(fd, &tail[got], n - got, static_cast<off_t>(size - n + got));
        if (r < 0) {
            if (errno == EINTR) continue;
            return Status::IoError;
        }
        if (r == 0) break;
        got += static_cast<std::size_t>(r);
    }
    if (got != n || tail.back() != '\n') return Status::FormatError;  // partial record
    tail.pop_back();
    const std::size_t p = tail.rfind('\n');
    std::string last;
    if (p == std::string::npos) {
        if (n < size) return Status::FormatError;
        last = tail;
    } else {
        last = tail.substr(p + 1);
    }
    Record prev;
    if (!parse_line(last, prev)) return Status::FormatError;
    std::uint8_t h[kHashLen];
    if (!sha256(last, h)) return Status::CryptoError;
    head.seq = prev.seq;
    head.hash_hex = to_hex(h, sizeof h);
    return Status::Ok;
}

// Aligns the evolving key state with the log tail (also recovers from a crash that
// happened after a record was written but before the anchor/state were updated).
static Status sync_state(const std::string& state_file, const std::string& anchor_file,
                         const Head& head, ChainState& cs) {
    if (head.seq + 1 == cs.index) return Status::Ok;
    if (head.seq == cs.index) {
        // Record `head.seq` exists but its key is still current: finish the interrupted
        // step (anchor it, then ratchet forward) before doing anything else.
        Status s = write_anchor(anchor_file, head.seq, head.hash_hex, cs.ck);
        if (s != Status::Ok) return s;
        SecretKey nx;
        if (!next_chain_key(cs.ck, nx.k)) return Status::CryptoError;
        cs.ck = nx.k;
        cs.index += 1;
        return save_state(state_file, cs);
    }
    // State is ahead of / unrelated to the log: records were removed or the log was
    // replaced. Refuse to extend a log we cannot account for.
    return Status::FormatError;
}

// Core writer: sanitizes, encrypts under the per-record key, appends, anchors, then
// ratchets the chain key forward (erasing the key that protected this record).
Status SecureLogger::append_record(const std::string& actor_in, Severity sev,
                                   const std::string& message) {
    std::string plain;
    if (!sanitize_message(message, plain)) return Status::InvalidInput;
    const std::string actor = is_valid_name(actor_in) ? actor_in : "unknown";

    int fd = ::open(log_path().c_str(), O_RDWR | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return Status::IoError;
    Fd g(fd);
    if (flock(fd, LOCK_EX) != 0) return Status::IoError;

    struct stat st{};
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || (st.st_mode & 022) != 0)
        return Status::IoError;

    ChainState cs;
    Status s = load_state(state_path(), cs);
    if (s != Status::Ok) return s;
    Head head;
    s = read_head(fd, st, head);
    if (s != Status::Ok) return s;
    s = sync_state(state_path(), anchor_path(), head, cs);
    if (s != Status::Ok) return s;

    const std::uint64_t seq = cs.index;  // == head.seq + 1
    std::uint8_t iv[kIvLen];
    if (!random_bytes(iv, sizeof iv)) return Status::CryptoError;

    const std::string ts = utc_now();
    const std::string sev_s = to_string(sev);
    const std::string aad = make_aad(seq, ts, sev_s, actor, cs.key_id, head.hash_hex);

    SecretKey ek;
    if (!record_enc_key(cs.ck, ek.k)) return Status::CryptoError;
    std::vector<std::uint8_t> ct;
    std::uint8_t tag[kTagLen];
    if (!gcm_encrypt(ek.k, iv, aad, plain, ct, tag)) return Status::CryptoError;

    // On-disk field order: SL1|seq|ts|sev|actor|keyid|iv|ct|tag|prev
    const std::string body = std::string(kMagic) + "|" + std::to_string(seq) + "|" + ts + "|" +
                             sev_s + "|" + actor + "|" + std::to_string(cs.key_id) + "|" +
                             to_hex(iv, sizeof iv) + "|" + to_hex(ct.data(), ct.size()) + "|" +
                             to_hex(tag, sizeof tag) + "|" + head.hash_hex;
    if (!write_all(fd, body + "\n")) return Status::IoError;
    if (fsync(fd) != 0) return Status::IoError;

    std::uint8_t h[kHashLen];
    if (!sha256(body, h)) return Status::CryptoError;
    s = write_anchor(anchor_path(), seq, to_hex(h, sizeof h), cs.ck);
    if (s != Status::Ok) return s;

    // Forward security: derive CK[seq+1], persist it, and let CK[seq] disappear.
    SecretKey nx;
    if (!next_chain_key(cs.ck, nx.k)) return Status::CryptoError;
    cs.ck = nx.k;
    cs.index = seq + 1;
    return save_state(state_path(), cs);
}

// Verifies the full log (sequence, hash chain, per-record GCM tags under the derived
// forward-secure keys, IV uniqueness, authenticated anchor and optional external
// checkpoint) and optionally returns decrypted entries. Stops at the first failure.
Status SecureLogger::scan(std::vector<Entry>* out, VerifyReport& rep, const Checkpoint* expect) {
    rep = VerifyReport{};
    KeyRing ring;
    Status ks = ring.load(keys_path());
    if (ks != Status::Ok) return ks;

    auto fail = [&](std::uint64_t at, const char* why) {
        rep.ok = false;
        rep.bad_seq = at;
        rep.reason = why;
        return Status::TamperDetected;
    };

    Anchor anchor;
    Status as = load_anchor(anchor_path(), anchor);
    if (as == Status::FormatError) return fail(1, "anchor file malformed");
    if (as != Status::Ok) return as;

    int fd = ::open(log_path().c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        if (errno != ENOENT) return Status::IoError;
        if (anchor.present) return fail(1, "log file missing but anchor exists");
        if (expect) return fail(1, "log shorter than external checkpoint");
        rep.ok = true;
        rep.head_hash = kZeroHash;
        return Status::Ok;
    }
    Fd g(fd);
    struct stat st{};
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || (st.st_mode & 022) != 0)
        return Status::IoError;
    if (flock(fd, LOCK_SH) != 0) return Status::IoError;
    std::string data;
    if (!read_fd_all(fd, data)) return Status::IoError;

    std::vector<Entry> entries;
    std::set<std::string> seen_iv;
    std::string prev_hex = kZeroHash;
    std::uint64_t idx = 0;
    std::size_t pos = 0;
    std::uint32_t cur_kid = 0;
    SecretKey ck;  // verifier-side re-derivation of the chain key CK[idx]

    while (pos < data.size()) {
        std::size_t nl = data.find('\n', pos);
        ++idx;
        if (nl == std::string::npos) return fail(idx, "incomplete or truncated record");
        std::string line = data.substr(pos, nl - pos);
        pos = nl + 1;

        Record r;
        if (!parse_line(line, r)) return fail(idx, "malformed record");
        if (r.seq != idx) return fail(idx, "sequence mismatch (record deleted, duplicated or reordered)");
        if (r.prev_hex != prev_hex) return fail(idx, "hash chain broken");

        if (r.key_id != cur_kid) {  // a new epoch starts at this record
            if (r.key_id < cur_kid) return fail(idx, "key id regression");
            const Key* root = ring.get(r.key_id);
            if (!root) return fail(idx, "unknown key id");
            if (!derive_start_key(*root, r.seq, ck.k)) return Status::CryptoError;
            cur_kid = r.key_id;
        }

        std::string ivs(reinterpret_cast<const char*>(r.iv.data()), r.iv.size());
        if (!seen_iv.insert(ivs).second) return fail(idx, "IV reuse detected");

        SecretKey ek;
        if (!record_enc_key(ck.k, ek.k)) return Status::CryptoError;
        std::string plain;
        if (!gcm_decrypt(ek.k, r.iv.data(), r.aad, r.ct, r.tag.data(), plain))
            return fail(idx, "authentication tag mismatch");

        if (out) {
            Entry e;
            Severity sv = Severity::Info;
            parse_severity(r.sev, sv);
            e.seq = r.seq;
            e.timestamp = r.ts;
            e.severity = sv;
            e.actor = r.actor;
            e.message = plain;
            entries.push_back(std::move(e));
        }
        OPENSSL_cleanse(&plain[0], plain.size());

        std::uint8_t h[kHashLen];
        if (!sha256(line, h)) return Status::CryptoError;
        const std::string hash_hex = to_hex(h, sizeof h);

        if (anchor.present && idx == anchor.seq) {
            Key expect_mac{};
            if (!anchor_mac(ck.k, idx, hash_hex, expect_mac)) return Status::CryptoError;
            if (anchor.hash != hash_hex || anchor.mac.size() != 32 ||
                CRYPTO_memcmp(expect_mac.data(), anchor.mac.data(), 32) != 0)
                return fail(idx, "authenticated anchor does not match record");
        }
        if (expect && idx == expect->seq && hash_hex != expect->hash)
            return fail(idx, "record differs from external checkpoint");

        SecretKey nx;  // ratchet forward: CK[idx+1]
        if (!next_chain_key(ck.k, nx.k)) return Status::CryptoError;
        ck.k = nx.k;
        prev_hex = hash_hex;
        rep.records = idx;
    }

    // End-of-log checks: this is what catches records cut off the tail.
    if (anchor.present && anchor.seq > idx)
        return fail(idx + 1, "log truncated: shorter than authenticated anchor");
    if (!anchor.present && idx > 0) return fail(idx, "authenticated anchor missing");
    if (expect && expect->seq > idx)
        return fail(idx + 1, "log shorter than external checkpoint");

    rep.ok = true;
    rep.head_hash = prev_hex;
    if (out) *out = std::move(entries);
    return Status::Ok;
}

// Zero Trust gate: authenticate explicitly, authorize against least-privilege
// policy, deny by default, and record failures in the encrypted log.
Status SecureLogger::authorize_request(const Credentials& who, Action action, Identity& id) {
    Status s = ac_.authenticate(who, id);
    if (s != Status::Ok) {
        if (s == Status::AuthFailed) {
            std::string u = is_valid_name(who.user) ? who.user : "<invalid>";
            append_record("unknown", Severity::Warn,
                          std::string("AUTH_FAILED user=") + u + " action=" + to_string(action));
        }
        return s;
    }
    if (!is_authorized(id.role, action)) {
        append_record(id.user, Severity::Warn,
                      std::string("ACCESS_DENIED role=") + to_string(id.role) +
                          " action=" + to_string(action));
        return Status::Denied;
    }
    return Status::Ok;
}

Status SecureLogger::append(const Credentials& who, Severity sev, const std::string& message) {
    Identity id;
    Status s = authorize_request(who, Action::Write, id);
    if (s != Status::Ok) return s;
    return append_record(id.user, sev, message);
}

Status SecureLogger::verify(const Credentials& who, VerifyReport& report,
                            const Checkpoint* expect) {
    report = VerifyReport{};
    Identity id;
    Status s = authorize_request(who, Action::Verify, id);
    if (s != Status::Ok) return s;
    // Scan BEFORE writing the audit record: appending refreshes the anchor, which
    // must not be allowed to repair tamper evidence before it has been examined.
    Status sc = scan(nullptr, report, expect);
    if (sc == Status::TamperDetected) {
        append_record(id.user, Severity::Critical,
                      "TAMPER_DETECTED record=" + std::to_string(report.bad_seq));
        return sc;
    }
    if (sc != Status::Ok) return sc;
    // Fails closed: if the log tail cannot be extended (e.g. the host was rolled back
    // behind the key state) this surfaces as an error rather than a clean bill of health.
    return append_record(id.user, Severity::Info, "VERIFY_REQUEST");
}

Status SecureLogger::checkpoint(const Credentials& who, Checkpoint& out) {
    out = Checkpoint{};
    VerifyReport rep;
    Identity id;
    Status s = authorize_request(who, Action::Verify, id);
    if (s != Status::Ok) return s;
    Status sc = scan(nullptr, rep, nullptr);
    if (sc == Status::TamperDetected) {
        append_record(id.user, Severity::Critical,
                      "TAMPER_DETECTED record=" + std::to_string(rep.bad_seq));
        return sc;  // never certify a log that fails verification
    }
    if (sc != Status::Ok) return sc;
    Status audit = append_record(id.user, Severity::Info, "CHECKPOINT_REQUEST");
    if (audit != Status::Ok) return audit;
    out.seq = rep.records;
    out.hash = rep.head_hash;
    return Status::Ok;
}

Status SecureLogger::read(const Credentials& who, std::vector<Entry>& out, VerifyReport* report) {
    out.clear();
    VerifyReport local;
    VerifyReport& rep = report ? *report : local;
    rep = VerifyReport{};
    Identity id;
    Status s = authorize_request(who, Action::Read, id);
    if (s != Status::Ok) return s;
    // 1. Verify first (see verify()); nothing is released from a log that fails.
    std::vector<Entry> tmp;
    Status sc = scan(&tmp, rep, nullptr);
    if (sc == Status::TamperDetected) {
        append_record(id.user, Severity::Critical,
                      "TAMPER_DETECTED record=" + std::to_string(rep.bad_seq));
        return sc;
    }
    if (sc != Status::Ok) return sc;
    // 2. Record the access BEFORE releasing any plaintext; refuse if it cannot be recorded.
    Status audit = append_record(id.user, Severity::Info, "READ_REQUEST");
    if (audit != Status::Ok) return audit;
    out = std::move(tmp);
    return Status::Ok;
}

Status SecureLogger::add_user(const Credentials& who, const std::string& name, Role role,
                              std::string& token_out) {
    Identity id;
    Status s = authorize_request(who, Action::ManageUsers, id);
    if (s != Status::Ok) return s;
    if (!is_valid_name(name)) return Status::InvalidInput;
    Status a = append_record(id.user, Severity::Info,
                             std::string("USER_ADD_REQUEST name=") + name + " role=" + to_string(role));
    if (a != Status::Ok) return a;
    return ac_.add_user(name, role, token_out);
}

// Starts a new epoch: the chain restarts from the NEW root key at the next sequence
// number, and nothing derived from the previous epoch remains on this host.
Status SecureLogger::switch_epoch(std::uint32_t new_key_id) {
    KeyRing ring;
    Status s = ring.load(keys_path());
    if (s != Status::Ok) return s;
    const Key* root = ring.get(new_key_id);
    if (!root) return Status::KeyError;

    int fd = ::open(log_path().c_str(), O_RDWR | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return Status::IoError;
    Fd g(fd);
    if (flock(fd, LOCK_EX) != 0) return Status::IoError;
    struct stat st{};
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || (st.st_mode & 022) != 0)
        return Status::IoError;

    ChainState cs;
    s = load_state(state_path(), cs);
    if (s != Status::Ok) return s;
    Head head;
    s = read_head(fd, st, head);
    if (s != Status::Ok) return s;
    s = sync_state(state_path(), anchor_path(), head, cs);
    if (s != Status::Ok) return s;

    SecretKey start;
    if (!derive_start_key(*root, cs.index, start.k)) return Status::CryptoError;
    cs.ck = start.k;
    cs.key_id = new_key_id;
    return save_state(state_path(), cs);
}

Status SecureLogger::rotate_key(const Credentials& who, std::uint32_t* new_id) {
    Identity id;
    Status s = authorize_request(who, Action::RotateKey, id);
    if (s != Status::Ok) return s;
    Status a = append_record(id.user, Severity::Info, "KEY_ROTATE_REQUEST");
    if (a != Status::Ok) return a;
    std::uint32_t nid = 0;
    s = KeyRing::rotate(keys_path(), nid);
    if (s != Status::Ok) return s;
    s = switch_epoch(nid);
    if (s != Status::Ok) return s;
    if (new_id) *new_id = nid;
    // This entry is the first record of the new epoch.
    return append_record(id.user, Severity::Info, "KEY_ROTATED new_key_id=" + std::to_string(nid));
}

}  // namespace securelog
