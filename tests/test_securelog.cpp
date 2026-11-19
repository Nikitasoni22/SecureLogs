// test_securelog.cpp - self-contained tests (no external framework).
// Covers the attack cases from the project objectives: unauthorized access,
// altered ciphertext, invalid authentication tag, malicious log input, plus
// reordering/deletion/replay/truncation, IV uniqueness, key handling & rotation.
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "securelog.hpp"

using namespace securelog;
namespace fs = std::filesystem;

static int g_pass = 0, g_fail = 0;
#define CHECK(c)                                                              \
    do {                                                                      \
        if (c) {                                                              \
            ++g_pass;                                                         \
        } else {                                                              \
            ++g_fail;                                                         \
            std::fprintf(stderr, "    FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); \
        }                                                                     \
    } while (0)

// ------------------------------------------------------------------ helpers
static std::vector<std::string> split(const std::string& s, char d) {
    std::vector<std::string> v;
    std::string cur;
    for (char c : s) {
        if (c == d) { v.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    v.push_back(cur);
    return v;
}
static std::string join(const std::vector<std::string>& v, char d) {
    std::string s;
    for (size_t i = 0; i < v.size(); ++i) { if (i) s.push_back(d); s += v[i]; }
    return s;
}
static std::vector<std::string> read_lines(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    std::vector<std::string> v;
    std::string l;
    while (std::getline(f, l)) v.push_back(l);
    return v;
}
static void write_lines(const std::string& p, const std::vector<std::string>& v) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    for (const auto& l : v) f << l << '\n';
}
static std::string slurp(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}
// field indices on disk: 0 SL1,1 seq,2 ts,3 sev,4 actor,5 keyid,6 iv,7 ct,8 tag,9 prev
static std::string with_field(const std::string& line, size_t idx, const std::string& val) {
    auto f = split(line, '|');
    f[idx] = val;
    return join(f, '|');
}
static std::string flip_first_hex(std::string h) {
    if (h.empty()) return h;
    h[0] = (h[0] == '0') ? '1' : '0';
    return h;
}

struct Fixture {
    std::string root;
    std::unique_ptr<SecureLogger> lg;
    Credentials admin, logger, auditor;

    Fixture() {
        char tmpl[] = "/tmp/securelog_test_XXXXXX";
        root = mkdtemp(tmpl);
        Config c;
        c.dir = root + "/data";
        c.pbkdf2_iters = 1000;  // fast for tests; production default is 210000
        lg.reset(new SecureLogger(c));
        std::string tok;
        CHECK(lg->init("root", tok) == Status::Ok);
        admin = {"root", tok};
        CHECK(lg->add_user(admin, "alice", Role::Logger, tok) == Status::Ok);
        logger = {"alice", tok};
        CHECK(lg->add_user(admin, "bob", Role::Auditor, tok) == Status::Ok);
        auditor = {"bob", tok};
    }
    ~Fixture() { std::error_code ec; fs::remove_all(root, ec); }
    void log_n(int n) {
        for (int i = 0; i < n; ++i)
            CHECK(lg->append(logger, Severity::Info, "event number " + std::to_string(i)) == Status::Ok);
    }
};

// -------------------------------------------------------------------- tests
static void test_roundtrip_and_confidentiality() {
    Fixture f;
    const std::string secret = "user password reset token=super-secret-value-123";
    CHECK(f.lg->append(f.logger, Severity::Warn, secret) == Status::Ok);
    CHECK(f.lg->append(f.logger, Severity::Error, "disk failure on /dev/sda") == Status::Ok);

    std::string raw = slurp(f.lg->log_path());
    CHECK(raw.find("super-secret-value-123") == std::string::npos);  // ciphertext only
    CHECK(raw.find("disk failure") == std::string::npos);

    std::vector<Entry> out;
    VerifyReport rep;
    CHECK(f.lg->read(f.auditor, out, &rep) == Status::Ok);
    CHECK(rep.ok);
    bool found1 = false, found2 = false;
    for (auto& e : out) {
        if (e.message == secret && e.actor == "alice" && e.severity == Severity::Warn) found1 = true;
        if (e.message == "disk failure on /dev/sda" && e.severity == Severity::Error) found2 = true;
    }
    CHECK(found1 && found2);
    // sequence numbers are contiguous from 1
    for (size_t i = 0; i < out.size(); ++i) CHECK(out[i].seq == i + 1);
}

static void test_zero_trust_authorization() {
    Fixture f;
    f.log_n(2);
    std::vector<Entry> out;
    VerifyReport rep;
    std::string tok;

    // wrong role -> Denied
    CHECK(f.lg->read(f.logger, out, &rep) == Status::Denied);
    CHECK(out.empty());
    CHECK(f.lg->verify(f.logger, rep) == Status::Denied);
    CHECK(f.lg->append(f.auditor, Severity::Info, "x") == Status::Denied);
    CHECK(f.lg->append(f.admin, Severity::Info, "x") == Status::Denied);
    CHECK(f.lg->read(f.admin, out, &rep) == Status::Denied);  // separation of duties
    CHECK(f.lg->add_user(f.auditor, "mallory", Role::Admin, tok) == Status::Denied);
    CHECK(f.lg->rotate_key(f.logger) == Status::Denied);
    // allowed
    CHECK(f.lg->verify(f.auditor, rep) == Status::Ok);
    CHECK(f.lg->verify(f.admin, rep) == Status::Ok);

    // authentication failures are indistinguishable
    CHECK(f.lg->append({"alice", "wrong-token"}, Severity::Info, "x") == Status::AuthFailed);
    CHECK(f.lg->append({"nobody", f.logger.token}, Severity::Info, "x") == Status::AuthFailed);
    CHECK(f.lg->append({"", ""}, Severity::Info, "x") == Status::AuthFailed);
    CHECK(f.lg->append({"alice", ""}, Severity::Info, "x") == Status::AuthFailed);
    CHECK(f.lg->append({"alice' OR '1'='1", "x"}, Severity::Info, "x") == Status::AuthFailed);
    CHECK(f.lg->read({"bob", f.admin.token}, out, &rep) == Status::AuthFailed);  // other user's token
    CHECK(out.empty());
}

static void test_audit_trail() {
    Fixture f;
    std::vector<Entry> out;
    VerifyReport rep;
    f.lg->append({"alice", "bad"}, Severity::Info, "x");   // auth failure
    f.lg->read(f.logger, out, &rep);                        // access denied
    CHECK(f.lg->read(f.auditor, out, &rep) == Status::Ok);   // records its own READ_REQUEST
    CHECK(f.lg->read(f.auditor, out, &rep) == Status::Ok);   // ...which the next read shows
    bool authfail = false, denied = false, readreq = false;
    for (auto& e : out) {
        if (e.message.find("AUTH_FAILED user=alice") != std::string::npos) authfail = true;
        if (e.message.find("ACCESS_DENIED role=logger action=read") != std::string::npos) denied = true;
        if (e.message == "READ_REQUEST" && e.actor == "bob") readreq = true;
    }
    CHECK(authfail);
    CHECK(denied);
    CHECK(readreq);
}

static void test_tamper_ciphertext_and_tag() {
    for (size_t field : {7u, 8u}) {  // ciphertext, then GCM tag
        Fixture f;
        f.log_n(4);
        auto lines = read_lines(f.lg->log_path());
        lines[1] = with_field(lines[1], field, flip_first_hex(split(lines[1], '|')[field]));
        write_lines(f.lg->log_path(), lines);

        VerifyReport rep;
        std::vector<Entry> out;
        CHECK(f.lg->verify(f.auditor, rep) == Status::TamperDetected);
        CHECK(rep.bad_seq == 2);
        CHECK(rep.reason.find("tag") != std::string::npos);
        CHECK(f.lg->read(f.auditor, out, &rep) == Status::TamperDetected);
        CHECK(out.empty());  // fail closed: no plaintext released from tampered log
    }
}

static void test_tamper_metadata_is_authenticated() {
    // severity, actor, timestamp and key id are plaintext on disk but bound as AAD.
    struct Case { size_t idx; std::string val; };
    for (Case c : {Case{3, "CRITICAL"}, Case{4, "mallory"}, Case{2, "2000-01-01T00:00:00Z"}}) {
        Fixture f;
        f.log_n(3);
        auto lines = read_lines(f.lg->log_path());
        if (split(lines[1], '|')[c.idx] == c.val) c.val = (c.idx == 3) ? "DEBUG" : c.val + "x";
        lines[1] = with_field(lines[1], c.idx, c.val);
        write_lines(f.lg->log_path(), lines);
        VerifyReport rep;
        CHECK(f.lg->verify(f.auditor, rep) == Status::TamperDetected);
        CHECK(rep.bad_seq == 2);
    }
}

static void test_delete_reorder_replay() {
    {   // delete a middle record
        Fixture f; f.log_n(5);
        auto l = read_lines(f.lg->log_path());
        l.erase(l.begin() + 2);
        write_lines(f.lg->log_path(), l);
        VerifyReport rep;
        CHECK(f.lg->verify(f.auditor, rep) == Status::TamperDetected);
        CHECK(rep.bad_seq == 3);
    }
    {   // swap two records
        Fixture f; f.log_n(5);
        auto l = read_lines(f.lg->log_path());
        std::swap(l[1], l[2]);
        write_lines(f.lg->log_path(), l);
        VerifyReport rep;
        CHECK(f.lg->verify(f.auditor, rep) == Status::TamperDetected);
        CHECK(rep.bad_seq == 2);
    }
    {   // replay (duplicate) the last record
        Fixture f; f.log_n(3);
        auto l = read_lines(f.lg->log_path());
        l.push_back(l.back());
        write_lines(f.lg->log_path(), l);
        VerifyReport rep;
        CHECK(f.lg->verify(f.auditor, rep) == Status::TamperDetected);
    }
    {   // delete the first record
        Fixture f; f.log_n(3);
        auto l = read_lines(f.lg->log_path());
        l.erase(l.begin());
        write_lines(f.lg->log_path(), l);
        VerifyReport rep;
        CHECK(f.lg->verify(f.auditor, rep) == Status::TamperDetected);
        CHECK(rep.bad_seq == 1);
    }
    {   // forge a record's prev-hash field
        Fixture f; f.log_n(3);
        auto l = read_lines(f.lg->log_path());
        l[2] = with_field(l[2], 9, std::string(64, 'a'));
        write_lines(f.lg->log_path(), l);
        VerifyReport rep;
        CHECK(f.lg->verify(f.auditor, rep) == Status::TamperDetected);
        CHECK(rep.bad_seq == 3);
    }
}

static void test_truncation_and_garbage() {
    {   // partial final record (e.g. truncated write)
        Fixture f; f.log_n(3);
        std::string raw = slurp(f.lg->log_path());
        raw.resize(raw.size() - 10);
        std::ofstream(f.lg->log_path(), std::ios::binary | std::ios::trunc) << raw;
        VerifyReport rep;
        CHECK(f.lg->verify(f.auditor, rep) == Status::TamperDetected);
        CHECK(f.lg->append(f.logger, Severity::Info, "after damage") != Status::Ok);  // refuses to append
    }
    {   // random garbage line
        Fixture f; f.log_n(2);
        auto l = read_lines(f.lg->log_path());
        l.push_back("not a record at all");
        write_lines(f.lg->log_path(), l);
        VerifyReport rep;
        CHECK(f.lg->verify(f.auditor, rep) == Status::TamperDetected);
    }
    {   // oversized / malformed fields must not crash the parser
        Fixture f; f.log_n(2);
        auto l = read_lines(f.lg->log_path());
        l[1] = with_field(l[1], 7, std::string(100000, 'a'));
        write_lines(f.lg->log_path(), l);
        VerifyReport rep;
        CHECK(f.lg->verify(f.auditor, rep) == Status::TamperDetected);
    }
}

static void test_log_injection_and_input_validation() {
    Fixture f;
    std::string evil = "login ok\n9999|2099-01-01T00:00:00Z|INFO|root|forged\x1b[31m red \r\t\x01";
    const size_t before = read_lines(f.lg->log_path()).size();  // setup wrote audit records
    CHECK(f.lg->append(f.logger, Severity::Info, evil) == Status::Ok);
    CHECK(read_lines(f.lg->log_path()).size() == before + 1);  // embedded newline made no extra record

    std::vector<Entry> out;
    VerifyReport rep;
    CHECK(f.lg->read(f.auditor, out, &rep) == Status::Ok);
    bool ok = false;
    for (auto& e : out) {
        if (e.message.rfind("login ok", 0) == 0) {
            ok = true;
            CHECK(e.message.find('\n') == std::string::npos);
            CHECK(e.message.find('\r') == std::string::npos);
            CHECK(e.message.find('\x1b') == std::string::npos);
            CHECK(e.message.find("\\n") != std::string::npos);
        }
    }
    CHECK(ok);

    CHECK(f.lg->append(f.logger, Severity::Info, "") == Status::InvalidInput);
    CHECK(f.lg->append(f.logger, Severity::Info, std::string(5000, 'A')) == Status::InvalidInput);
    CHECK(f.lg->append(f.logger, Severity::Info, std::string(2048, 'A')) == Status::Ok);
    std::string tok;
    CHECK(f.lg->add_user(f.admin, "bad|name", Role::Logger, tok) == Status::InvalidInput);
    CHECK(f.lg->add_user(f.admin, "alice", Role::Logger, tok) == Status::InvalidInput);  // duplicate
    CHECK(!is_valid_name("a:b") && !is_valid_name("") && !is_valid_name(std::string(33, 'a')));
}

static void test_iv_uniqueness() {
    Fixture f;
    f.log_n(300);
    std::set<std::string> ivs;
    for (auto& l : read_lines(f.lg->log_path())) ivs.insert(split(l, '|')[6]);
    CHECK(ivs.size() == read_lines(f.lg->log_path()).size());
    CHECK(ivs.size() >= 300);
    // forcing an IV repeat is detected
    auto l = read_lines(f.lg->log_path());
    l[5] = with_field(l[5], 6, split(l[4], '|')[6]);
    write_lines(f.lg->log_path(), l);
    VerifyReport rep;
    CHECK(f.lg->verify(f.auditor, rep) == Status::TamperDetected);
}

static void test_key_handling() {
    {   // root key readable by group/other -> verifier refuses to use it
        Fixture f; f.log_n(1);
        fs::permissions(f.lg->keys_path(), fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read);
        VerifyReport rep;
        CHECK(f.lg->verify(f.auditor, rep) == Status::KeyError);
    }
    {   // evolving state key readable by group/other -> writer refuses to use it
        Fixture f; f.log_n(1);
        fs::permissions(f.lg->state_path(), fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read);
        CHECK(f.lg->append(f.logger, Severity::Info, "x") == Status::KeyError);
    }
    {   // corrupted state file -> fail closed
        Fixture f; f.log_n(1);
        std::ofstream(f.lg->state_path(), std::ios::trunc) << "garbage\n";
        fs::permissions(f.lg->state_path(), fs::perms::owner_read | fs::perms::owner_write);
        CHECK(f.lg->append(f.logger, Severity::Info, "x") == Status::KeyError);
    }
    {   // missing key file
        Fixture f; f.log_n(1);
        fs::remove(f.lg->keys_path());
        VerifyReport rep;
        CHECK(f.lg->verify(f.auditor, rep) == Status::KeyError);
    }
    {   // wrong key -> every tag fails
        Fixture f; f.log_n(2);
        std::ofstream(f.lg->keys_path(), std::ios::trunc) << "1:" << std::string(64, '1') << "\n";
        fs::permissions(f.lg->keys_path(), fs::perms::owner_read | fs::perms::owner_write);
        VerifyReport rep;
        CHECK(f.lg->verify(f.auditor, rep) == Status::TamperDetected);
        CHECK(rep.bad_seq == 1);
    }
    {   // file modes are restrictive
        Fixture f; f.log_n(1);
        struct stat st{};
        CHECK(stat(f.lg->keys_path().c_str(), &st) == 0 && (st.st_mode & 077) == 0);
        CHECK(stat(f.lg->state_path().c_str(), &st) == 0 && (st.st_mode & 077) == 0);
        CHECK(stat(f.lg->anchor_path().c_str(), &st) == 0 && (st.st_mode & 077) == 0);
        CHECK(stat(f.lg->users_path().c_str(), &st) == 0 && (st.st_mode & 077) == 0);
        CHECK(stat(f.lg->log_path().c_str(), &st) == 0 && (st.st_mode & 077) == 0);
    }
    {   // users file world readable -> fail closed
        Fixture f;
        fs::permissions(f.lg->users_path(), fs::perms::owner_read | fs::perms::owner_write | fs::perms::others_read);
        CHECK(f.lg->append(f.logger, Severity::Info, "x") != Status::Ok);
    }
}

static void test_key_rotation() {
    Fixture f;
    f.log_n(2);
    std::uint32_t nid = 0;
    CHECK(f.lg->rotate_key(f.admin, &nid) == Status::Ok);
    CHECK(nid == 2);
    f.log_n(2);
    std::set<std::string> kids;
    for (auto& l : read_lines(f.lg->log_path())) kids.insert(split(l, '|')[5]);
    CHECK(kids.count("1") == 1 && kids.count("2") == 1);
    std::vector<Entry> out;
    VerifyReport rep;
    CHECK(f.lg->read(f.auditor, out, &rep) == Status::Ok);  // old + new records both readable
    CHECK(rep.ok);
    CHECK(f.lg->rotate_key(f.admin, &nid) == Status::Ok && nid == 3);
}

static void test_concurrent_writers() {
    Fixture f;
    const int kProcs = 4, kEach = 25;
    std::vector<pid_t> kids;
    for (int p = 0; p < kProcs; ++p) {
        pid_t pid = fork();
        if (pid == 0) {
            Config c; c.dir = f.root + "/data"; c.pbkdf2_iters = 1000;
            SecureLogger lg(c);
            int bad = 0;
            for (int i = 0; i < kEach; ++i)
                if (lg.append(f.logger, Severity::Info, "p" + std::to_string(p) + " m" + std::to_string(i)) != Status::Ok) ++bad;
            _exit(bad ? 1 : 0);
        }
        kids.push_back(pid);
    }
    for (pid_t pid : kids) {
        int st = 0;
        waitpid(pid, &st, 0);
        CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0);
    }
    VerifyReport rep;
    CHECK(f.lg->verify(f.auditor, rep) == Status::Ok);
    CHECK(rep.records >= static_cast<unsigned>(kProcs * kEach));
}


// ------------------------------------------------ truncation protection (anchor)
static void test_tail_truncation_detected() {
    {   // cut the last records off the log
        Fixture f; f.log_n(6);
        auto l = read_lines(f.lg->log_path());
        l.resize(l.size() - 3);
        write_lines(f.lg->log_path(), l);
        VerifyReport rep; std::vector<Entry> out;
        CHECK(f.lg->verify(f.auditor, rep) == Status::TamperDetected);
        CHECK(rep.reason.find("truncated") != std::string::npos);
        CHECK(f.lg->read(f.auditor, out, &rep) == Status::TamperDetected);
        CHECK(out.empty());
        // the writer also refuses to extend a log it cannot account for
        CHECK(f.lg->append(f.logger, Severity::Info, "after truncation") != Status::Ok);
    }
    {   // cut the tail AND delete the anchor
        Fixture f; f.log_n(6);
        auto l = read_lines(f.lg->log_path());
        l.resize(l.size() - 2);
        write_lines(f.lg->log_path(), l);
        fs::remove(f.lg->anchor_path());
        VerifyReport rep;
        CHECK(f.lg->verify(f.auditor, rep) == Status::TamperDetected);
        CHECK(rep.reason.find("anchor") != std::string::npos);
    }
    {   // forge an anchor for the shorter log (no chain key -> MAC cannot be valid)
        Fixture f; f.log_n(6);
        auto l = read_lines(f.lg->log_path());
        l.resize(l.size() - 2);
        write_lines(f.lg->log_path(), l);
        std::ofstream(f.lg->anchor_path(), std::ios::trunc)
            << l.size() << ":" << std::string(64, 'a') << ":" << std::string(64, 'b') << "\n";
        fs::permissions(f.lg->anchor_path(), fs::perms::owner_read | fs::perms::owner_write);
        VerifyReport rep;
        CHECK(f.lg->verify(f.auditor, rep) == Status::TamperDetected);
    }
    {   // anchor swapped for one from another log
        Fixture f1; f1.log_n(4);
        Fixture f2; f2.log_n(4);
        fs::copy_file(f2.lg->anchor_path(), f1.lg->anchor_path(), fs::copy_options::overwrite_existing);
        fs::permissions(f1.lg->anchor_path(), fs::perms::owner_read | fs::perms::owner_write);
        VerifyReport rep;
        CHECK(f1.lg->verify(f1.auditor, rep) == Status::TamperDetected);
    }
    {   // whole log file deleted
        Fixture f; f.log_n(3);
        fs::remove(f.lg->log_path());
        VerifyReport rep;
        CHECK(f.lg->verify(f.auditor, rep) == Status::TamperDetected);
    }
    {   // malformed anchor
        Fixture f; f.log_n(3);
        std::ofstream(f.lg->anchor_path(), std::ios::trunc) << "nonsense\n";
        fs::permissions(f.lg->anchor_path(), fs::perms::owner_read | fs::perms::owner_write);
        VerifyReport rep;
        CHECK(f.lg->verify(f.auditor, rep) == Status::TamperDetected);
    }
}

// Crash between "record written" and "anchor/state updated" must self-heal, not
// be mistaken for an attack by the next writer.
static void test_crash_recovery() {
    Fixture f; f.log_n(3);
    const std::string state_before = slurp(f.lg->state_path());
    const std::string anchor_before = slurp(f.lg->anchor_path());
    f.log_n(1);  // pretend this append crashed after writing the record:
    {
        std::ofstream(f.lg->state_path(), std::ios::trunc) << state_before;
        std::ofstream(f.lg->anchor_path(), std::ios::trunc) << anchor_before;
        fs::permissions(f.lg->state_path(), fs::perms::owner_read | fs::perms::owner_write);
        fs::permissions(f.lg->anchor_path(), fs::perms::owner_read | fs::perms::owner_write);
    }
    // state is now ONE record behind the log (record present, key not yet ratcheted)
    CHECK(f.lg->append(f.logger, Severity::Info, "post-crash write") == Status::Ok);
    VerifyReport rep;
    CHECK(f.lg->verify(f.auditor, rep) == Status::Ok);
    CHECK(rep.ok);
}

// ---------------------------------------------------------- forward security
static Key key_from_hex(const std::string& h) {
    Key k{};
    for (size_t i = 0; i < 32; ++i) k[i] = static_cast<uint8_t>(std::stoi(h.substr(2 * i, 2), nullptr, 16));
    return k;
}
static Key read_state_key(const std::string& path, uint64_t* index = nullptr) {
    std::string st = slurp(path);
    auto f = split(st.substr(0, st.size() - 1), ':');   // index:keyid:hex
    if (index) *index = std::stoull(f[0]);
    return key_from_hex(f[2]);
}

static void test_forward_security() {
    Fixture f; f.log_n(6);
    auto lines = read_lines(f.lg->log_path());

    // 1. The verifier (holding the root key) can re-derive every record key.
    std::string kf = slurp(f.lg->keys_path());
    Key root = key_from_hex(split(kf.substr(0, kf.size() - 1), ':')[1]);
    {
        Key ck{};
        CHECK(derive_start_key(root, 1, ck));
        int ok = 0;
        for (auto& l : lines) {
            Key ek{}; std::string pt;
            CHECK(record_enc_key(ck, ek));
            if (decrypt_record_line(l, ek, pt)) ++ok;
            Key nx{}; CHECK(next_chain_key(ck, nx)); ck = nx;
        }
        CHECK(ok == static_cast<int>(lines.size()));
    }

    // 2. An attacker who steals the host's current key state AFTER these records were
    //    written cannot decrypt any of them, however far forward he ratchets.
    uint64_t j = 0;
    Key stolen = read_state_key(f.lg->state_path(), &j);
    CHECK(j == lines.size() + 1);
    {
        Key k = stolen;
        int cracked = 0;
        for (int step = 0; step < 16; ++step) {
            Key ek{}; record_enc_key(k, ek);
            for (auto& l : lines) { std::string pt; if (decrypt_record_line(l, ek, pt)) ++cracked; }
            Key nx{}; next_chain_key(k, nx); k = nx;
        }
        CHECK(cracked == 0);
    }

    // 3. The on-disk state really is overwritten on each append (one-way ratchet).
    CHECK(f.lg->append(f.logger, Severity::Info, "one more") == Status::Ok);
    uint64_t j2 = 0;
    Key now = read_state_key(f.lg->state_path(), &j2);
    CHECK(j2 == j + 1);
    CHECK(now != stolen);
    Key expected{}; CHECK(next_chain_key(stolen, expected));
    CHECK(now == expected);  // moves forward only; the old key is gone from disk

    // 4. The logging host does not need the root key: remove it and keep logging.
    const std::string root_backup = kf;
    fs::remove(f.lg->keys_path());
    CHECK(f.lg->append(f.logger, Severity::Info, "written with root key absent") == Status::Ok);
    VerifyReport rep;
    CHECK(f.lg->verify(f.auditor, rep) == Status::KeyError);   // cannot verify without it
    { std::ofstream(f.lg->keys_path(), std::ios::trunc) << root_backup; }
    fs::permissions(f.lg->keys_path(), fs::perms::owner_read | fs::perms::owner_write);
    CHECK(f.lg->verify(f.auditor, rep) == Status::Ok);          // ...and it all verifies
    std::vector<Entry> out;
    CHECK(f.lg->read(f.auditor, out, &rep) == Status::Ok);
    bool found = false;
    for (auto& e : out) if (e.message == "written with root key absent") found = true;
    CHECK(found);
}

static void test_forward_security_across_rotation() {
    Fixture f; f.log_n(3);
    uint32_t nid = 0;
    CHECK(f.lg->rotate_key(f.admin, &nid) == Status::Ok);
    f.log_n(3);
    // after rotation, the host state is derived from the NEW root key only
    uint64_t j = 0;
    Key cur = read_state_key(f.lg->state_path(), &j);
    auto lines = read_lines(f.lg->log_path());
    int cracked = 0;
    Key k = cur;
    for (int step = 0; step < 16; ++step) {
        Key ek{}; record_enc_key(k, ek);
        for (auto& l : lines) { std::string pt; if (decrypt_record_line(l, ek, pt)) ++cracked; }
        Key nx{}; next_chain_key(k, nx); k = nx;
    }
    CHECK(cracked == 0);
    VerifyReport rep;
    CHECK(f.lg->verify(f.auditor, rep) == Status::Ok);
    // records from both epochs verify, and the key ids are non-decreasing
    std::string prev = "0";
    for (auto& l : lines) {
        std::string kid = split(l, '|')[5];
        CHECK(std::stoul(kid) >= std::stoul(prev));
        prev = kid;
    }
    // a tampered key-id regression is rejected
    lines[lines.size() - 1] = with_field(lines.back(), 5, "1");
    write_lines(f.lg->log_path(), lines);
    CHECK(f.lg->verify(f.auditor, rep) == Status::TamperDetected);
}

// ------------------------------------------------- external checkpoint (rollback)
static void test_external_checkpoint() {
    Fixture f; f.log_n(3);
    // attacker-controlled snapshot of the ENTIRE host state taken now
    auto snap = [&](const std::string& src, const std::string& dst) {
        fs::copy_file(src, dst, fs::copy_options::overwrite_existing);
        fs::permissions(dst, fs::perms::owner_read | fs::perms::owner_write);
    };
    snap(f.lg->log_path(), f.root + "/snap.log");
    snap(f.lg->anchor_path(), f.root + "/snap.anchor");
    snap(f.lg->state_path(), f.root + "/snap.state");

    f.log_n(3);
    Checkpoint cp;
    CHECK(f.lg->checkpoint(f.auditor, cp) == Status::Ok);   // stored OFF-host by the auditor
    CHECK(cp.seq > 0 && cp.hash.size() == 64);
    Checkpoint parsed;
    CHECK(parse_checkpoint(to_string(cp), parsed) && parsed.seq == cp.seq && parsed.hash == cp.hash);
    CHECK(!parse_checkpoint("abc", parsed) && !parse_checkpoint("5:xyz", parsed) && !parse_checkpoint("0:" + cp.hash, parsed));

    f.log_n(2);
    VerifyReport rep;
    CHECK(f.lg->verify(f.auditor, rep, &cp) == Status::Ok);   // honest log satisfies it

    // Roll back log + anchor + state together: self-consistent, so local checks pass...
    snap(f.root + "/snap.log", f.lg->log_path());
    snap(f.root + "/snap.anchor", f.lg->anchor_path());
    snap(f.root + "/snap.state", f.lg->state_path());
    CHECK(f.lg->verify(f.auditor, rep) == Status::Ok);
    // ...but the off-host checkpoint exposes the rollback.
    CHECK(f.lg->verify(f.auditor, rep, &cp) == Status::TamperDetected);
    CHECK(rep.reason.find("checkpoint") != std::string::npos);

    // A checkpoint with the right sequence but wrong hash is rejected on an honest log.
    Fixture g; g.log_n(3);
    Checkpoint bad; bad.seq = 2; bad.hash = std::string(64, '0');
    CHECK(g.lg->verify(g.auditor, rep, &bad) == Status::TamperDetected);
    // checkpoints are only issued to authorized roles
    CHECK(g.lg->checkpoint(g.logger, cp) == Status::Denied);
}

static void test_empty_log_and_reinit() {
    Fixture f;
    VerifyReport rep;
    std::vector<Entry> out;
    CHECK(f.lg->read(f.auditor, out, &rep) == Status::Ok);  // only its own READ_REQUEST
    std::string tok;
    CHECK(f.lg->init("root2", tok) != Status::Ok);  // cannot re-initialize existing store
}

int main() {
    struct T { const char* name; void (*fn)(); };
    const T tests[] = {
        {"round trip & confidentiality", test_roundtrip_and_confidentiality},
        {"zero-trust authorization", test_zero_trust_authorization},
        {"audit trail of denied access", test_audit_trail},
        {"tampered ciphertext / GCM tag", test_tamper_ciphertext_and_tag},
        {"tampered metadata (AAD)", test_tamper_metadata_is_authenticated},
        {"delete / reorder / replay", test_delete_reorder_replay},
        {"truncation & garbage input", test_truncation_and_garbage},
        {"log injection & input validation", test_log_injection_and_input_validation},
        {"IV uniqueness & reuse detection", test_iv_uniqueness},
        {"key file handling (fail secure)", test_key_handling},
        {"key rotation", test_key_rotation},
        {"concurrent writers", test_concurrent_writers},
        {"tail truncation detected (anchor)", test_tail_truncation_detected},
        {"crash recovery", test_crash_recovery},
        {"forward security", test_forward_security},
        {"forward security across rotation", test_forward_security_across_rotation},
        {"external checkpoint (rollback)", test_external_checkpoint},
        {"empty log / re-init refused", test_empty_log_and_reinit},
    };
    for (const auto& t : tests) {
        int before = g_fail;
        t.fn();
        std::printf("[%s] %s\n", g_fail == before ? " OK " : "FAIL", t.name);
    }
    std::printf("\n%d checks passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
