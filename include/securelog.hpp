// securelog.hpp - Secure logging with AES-256-GCM encryption and Zero Trust access checks.
//
// Design summary (see README.md):
//   * Every record is encrypted with AES-256-GCM using a fresh random 96-bit IV.
//   * Record metadata (seq, timestamp, severity, actor, key id, prev hash) is bound
//     to the ciphertext as GCM Additional Authenticated Data (AAD).
//   * Records are linked by a SHA-256 hash chain (prev_record_hash) + sequence numbers,
//     so modification, deletion, duplication and reordering are detected.
//   * Every public operation authenticates the caller and authorizes the action
//     against a deny-by-default role policy (Logger / Auditor / Admin).
//   * Keys live in private files (0600), never in source code; rotation supported.
//   * FORWARD SECURITY: each record is encrypted under its own key taken from a one-way
//     hash ratchet (CK[i+1] = HMAC(CK[i], "next")). The logging host stores only the
//     CURRENT chain key and overwrites it after every record, so a key stolen later
//     cannot decrypt or re-forge earlier records. The root key (needed to re-derive the
//     chain for verification) is meant to live off the logging host.
//   * TRUNCATION PROTECTION: after every record the writer stores an authenticated
//     anchor (latest seq + record hash, MAC'd with that record's chain key). Cutting
//     records off the tail, or deleting the anchor, fails verification. A checkpoint
//     (seq:hash) can also be exported off-host and checked with verify(..., &checkpoint)
//     to catch a complete rollback of the host.
#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace securelog {

// ---------------------------------------------------------------- status codes
enum class Status {
    Ok = 0,
    AuthFailed,      // unknown user or bad token (deliberately indistinguishable)
    Denied,          // authenticated, but role may not perform this action
    InvalidInput,    // bad actor name, empty/oversized message, bad severity ...
    IoError,         // file / OS failure
    CryptoError,     // OpenSSL failure
    TamperDetected,  // tag mismatch, broken chain, bad sequence, IV reuse ...
    KeyError,        // key file missing, malformed, or has unsafe permissions
    FormatError      // log file is malformed in a way that blocks appending
};
const char* to_string(Status s);  // generic text only - never contains secrets

enum class Severity { Debug, Info, Warn, Error, Critical };
const char* to_string(Severity s);
bool parse_severity(const std::string& text, Severity& out);

// ------------------------------------------------------------------ zero trust
enum class Role { Logger, Auditor, Admin };
enum class Action { Write, Read, Verify, ManageUsers, RotateKey };

const char* to_string(Role r);
const char* to_string(Action a);
bool parse_role(const std::string& text, Role& out);

struct Credentials {
    std::string user;
    std::string token;
};

struct Identity {
    std::string user;
    Role role = Role::Logger;
};

// Least-privilege policy. Anything not explicitly allowed is denied.
//   Logger  : Write
//   Auditor : Read, Verify
//   Admin   : Verify, ManageUsers, RotateKey   (cannot read log contents)
bool is_authorized(Role role, Action action);

// ------------------------------------------------------------------------ keys
using Key = std::array<std::uint8_t, 32>;

class KeyRing {
public:
    KeyRing() = default;
    KeyRing(const KeyRing&) = delete;
    KeyRing& operator=(const KeyRing&) = delete;
    ~KeyRing();  // wipes key material

    // Loads "id:hex64" lines. Fails closed if the file is not a regular file
    // or is accessible by group/other (mode & 077).
    Status load(const std::string& path);
    // Creates a new key file (mode 0600, O_EXCL) containing key id 1.
    Status create(const std::string& path);
    // Appends a new random key with id = active+1 and returns its id.
    static Status rotate(const std::string& path, std::uint32_t& new_id);

    const Key* get(std::uint32_t id) const;
    std::uint32_t active_id() const { return active_; }

private:
    std::map<std::uint32_t, Key> keys_;
    std::uint32_t active_ = 0;
};

// ----------------------------------------------------------------- log entries
struct Entry {
    std::uint64_t seq = 0;
    std::string timestamp;  // UTC, ISO-8601
    Severity severity = Severity::Info;
    std::string actor;
    std::string message;    // decrypted event details (control characters escaped)
};

struct VerifyReport {
    bool ok = false;
    std::uint64_t records = 0;   // records successfully verified
    std::uint64_t bad_seq = 0;   // first failing record (1-based), 0 if none
    std::string reason;          // generic reason, no secret data
    std::string head_hash;       // hex SHA-256 of the last verified record
};

// An (sequence, record-hash) pair published OUTSIDE the logging host (WORM storage,
// SIEM, e-mail ...). Text form: "<seq>:<64 hex chars>".
struct Checkpoint {
    std::uint64_t seq = 0;
    std::string hash;
};
bool parse_checkpoint(const std::string& text, Checkpoint& out);
std::string to_string(const Checkpoint& c);

// Forward-secure key schedule primitives (exposed so tests / external verifiers can
// reproduce the derivation). All return false on an OpenSSL failure.
bool derive_start_key(const Key& root, std::uint64_t first_seq, Key& out);  // CK[first_seq]
bool next_chain_key(const Key& ck, Key& out);                               // CK[i+1]
bool record_enc_key(const Key& ck, Key& out);                               // per-record AES key
// Decrypts one on-disk record line with the given per-record key (no chain checks).
bool decrypt_record_line(const std::string& line, const Key& enc_key, std::string& plain);

// ----------------------------------------------------------------- user store
class AccessControl {
public:
    AccessControl(std::string users_path, std::uint32_t pbkdf2_iters);

    // Creates the users file with a first Admin (bootstrap). Fails if it exists.
    Status create_with_admin(const std::string& name, std::string& token_out);
    // Adds a user with a freshly generated random token (returned once).
    Status add_user(const std::string& name, Role role, std::string& token_out);
    // Verifies credentials (PBKDF2-HMAC-SHA256, constant-time compare).
    Status authenticate(const Credentials& c, Identity& id) const;

private:
    Status make_line(const std::string& name, Role role, std::string& token_out,
                     std::string& line) const;
    std::string path_;
    std::uint32_t iters_;
};

// -------------------------------------------------------------- secure logger
struct Config {
    std::string dir;                       // directory holding log, state, anchor and users
    std::string keys_file;                 // root key file; default <dir>/keys.db. Point this
                                           // at media that is NOT on the logging host.
    std::uint32_t pbkdf2_iters = 210000;   // for newly created user tokens
};

class SecureLogger {
public:
    explicit SecureLogger(Config cfg);

    // One-time setup: creates dir (0700), key file (0600) and first admin.
    Status init(const std::string& admin_name, std::string& admin_token_out);

    // Logger: encrypt and append one event.
    Status append(const Credentials& who, Severity sev, const std::string& message);
    // Auditor: verify the whole log, then return decrypted entries.
    // Fails closed: on any tamper nothing is returned.
    Status read(const Credentials& who, std::vector<Entry>& out, VerifyReport* report = nullptr);
    // Auditor / Admin: verify tags + chain + sequence + anchor without returning plaintext.
    // If `expect` is given, the log must also contain that externally stored checkpoint.
    Status verify(const Credentials& who, VerifyReport& report,
                  const Checkpoint* expect = nullptr);
    // Auditor / Admin: verify, then return a checkpoint of the current head to store off-host.
    Status checkpoint(const Credentials& who, Checkpoint& out);
    // Admin: add a user (token returned once).
    Status add_user(const Credentials& who, const std::string& name, Role role,
                    std::string& token_out);
    // Admin: generate a new active key; old keys are kept for decrypting old records.
    Status rotate_key(const Credentials& who, std::uint32_t* new_id = nullptr);

    std::string log_path() const;
    std::string keys_path() const;    // root keys (verifier side)
    std::string state_path() const;   // evolving chain key (logger side)
    std::string anchor_path() const;  // authenticated head anchor
    std::string users_path() const;

private:
    Status authorize_request(const Credentials& who, Action action, Identity& id);
    Status append_record(const std::string& actor, Severity sev, const std::string& message);
    Status scan(std::vector<Entry>* out, VerifyReport& report,
                const Checkpoint* expect = nullptr);
    Status switch_epoch(std::uint32_t new_key_id);

    Config cfg_;
    AccessControl ac_;
};

// Helpers exposed for tests / CLI.
bool is_valid_name(const std::string& s);
bool sanitize_message(const std::string& in, std::string& out);

}  // namespace securelog
