# Secure Logging with Encryption / Zero Trust

C++17 + OpenSSL EVP mini-project (CYE551, Phase I). Every log entry is encrypted with
**AES-256-GCM** under its own **forward-secure** key, records are chained with **SHA-256**
and anchored so tampering and **tail truncation** are detected, and every read/write passes
a **Zero Trust gate** (authenticate, authorize, least privilege, deny by default).

## Build and run

Requires `g++` (C++17), `make`, and OpenSSL development headers
(`sudo apt install build-essential libssl-dev`).

```bash
make          # builds build/securelog (CLI) and build/test_securelog
make test     # 708 checks covering the attack cases below
make demo     # end-to-end walkthrough: logging, denials, forward security, 5 attacks
```

### Recommended deployment

```
 LOGGING HOST (untrusted after compromise)      OFF-HOST (auditor / KMS / WORM)
 ------------------------------------------      --------------------------------
 securelog.enc   encrypted records               root.keys      root key(s)  [0600]
 state.key       CURRENT chain key only          checkpoints.txt  published SEQ:HASH lines
 anchor.mac      authenticated head anchor
 users.db        PBKDF2-hashed user tokens
```

The logging host can write but cannot decrypt; the root key is only needed to verify/read.

```bash
# one-time setup; root key is created directly on off-host media
./build/securelog init --dir ./host --keys /secure/root.keys --admin root   # prints ADMIN_TOKEN once

export SECURELOG_USER=root SECURELOG_TOKEN=<admin token>
./build/securelog adduser --dir ./host --keys /secure/root.keys --name alice --role logger
./build/securelog adduser --dir ./host --keys /secure/root.keys --name bob   --role auditor

# writers never need the root key
SECURELOG_USER=alice SECURELOG_TOKEN=<token> \
  ./build/securelog log --dir ./host --severity WARN --message "failed login for jdoe"

# auditor side
SECURELOG_USER=bob SECURELOG_TOKEN=<token> ./build/securelog read   --dir ./host --keys /secure/root.keys
SECURELOG_USER=bob SECURELOG_TOKEN=<token> ./build/securelog verify --dir ./host --keys /secure/root.keys

# publish a checkpoint off-host regularly (cron), and verify against it
./build/securelog checkpoint --dir ./host --keys /secure/root.keys >> /mnt/worm/checkpoints.txt
./build/securelog verify --dir ./host --keys /secure/root.keys --expect "$(tail -n1 /mnt/worm/checkpoints.txt | sed 's/CHECKPOINT=//')"

# new key epoch
SECURELOG_USER=root SECURELOG_TOKEN=<admin token> ./build/securelog rotate --dir ./host --keys /secure/root.keys
```

If `--keys` is omitted the root key is `DIR/keys.db` — convenient for experiments, but then
the host holds everything and **forward security does not apply** (see Limitations).

Credentials come from `SECURELOG_USER` / `SECURELOG_TOKEN`, not `argv` (visible via `ps`).
Exit codes: 1 auth failed, 2 denied, 3 invalid input, 4 I/O, 5 crypto, 6 tamper detected,
7 key error, 8 format error, 64 usage.

### Library use

```cpp
securelog::SecureLogger lg({"./host", "/secure/root.keys"});
lg.append({"alice", token}, securelog::Severity::Info, "backup completed");
std::vector<securelog::Entry> entries;
lg.read({"bob", token2}, entries);                 // verifies everything first; fails closed
securelog::Checkpoint cp; lg.checkpoint({"bob", token2}, cp);   // store to_string(cp) off-host
```

## Web demo dashboard

```bash
make                       # build the CLI once
python3 ui/server.py       # then open http://127.0.0.1:8080   (--port N to change)
```

A local page (Python standard library only, bound to 127.0.0.1) that drives the **real**
`securelog` binary, nothing is simulated. It shows:

* the raw file as an attacker sees it (IV, ciphertext, GCM tag, previous-record hash per
  record) plus a search box proving the plaintext is not present;
* the decrypted view for an auditor, released only after verification;
* login as `alice` (logger), `bob` (auditor), `root` (admin) or `mallory` (wrong token) to
  see Zero Trust denials;
* attack buttons (flip ciphertext bit, edit severity, delete, swap, tail truncation,
  truncation + anchor deletion, full host rollback) with the failing record highlighted
  red after **Verify**, and **Undo last attack**;
* the forward-secure key state changing after every write, and off-host checkpoints.

Demo-only: the server remembers the demo users' tokens so you can switch users from a
dropdown. Data lives in `ui/demo_data/` (use **Reset demo** to recreate it).

## How it maps to the project slides

| Slide objective / improvement | Where |
|---|---|
| Structured entries: timestamp, severity, actor, event | `Entry`, `append_record()` |
| AES-256-GCM, fresh random IV, auth tag | `gcm_encrypt/gcm_decrypt`, `RAND_bytes` per record |
| Zero Trust on every write and read | `authorize_request()`, `is_authorized()` |
| Detect modification/reordering via GCM tag + previous-record hash / sequence | `scan()` |
| Keys outside source, rotation, restricted permissions, safe errors | `KeyRing`, `open_private()`, generic `to_string(Status)` |
| Test unauthorized access, altered ciphertext, invalid tag, malicious input | `tests/test_securelog.cpp` |
| Literature: forward-secure audit logging (Schneier-Kelsey, Logcrypt, FAS) | key ratchet: `next_chain_key()`, `state.key` |
| Literature: truncation / stream completeness (Holt) | anchor + external checkpoints |
| Further improvements: KMS/HSM key, immutable remote storage | root key off-host (`--keys`), `checkpoint` to WORM |

### Record format (one line per record)

```
SL1|sequence|timestamp|severity|actor|key_id|IV|ciphertext|GCM_tag|prev_record_hash
```

* **AAD** = `SL1|sequence|timestamp|severity|actor|key_id|prev_record_hash`, so the
  plaintext metadata cannot be edited without invalidating the tag.
* `prev_record_hash` = SHA-256 of the entire previous line (all zeros for record 1).
  Deleting, duplicating or reordering records breaks the sequence/chain.

### Forward-secure key schedule

```
 root key R[e]  (off-host)
      | HMAC(R[e], "init" | first_seq)
      v
   CK[n]  --HMAC "next"-->  CK[n+1]  --HMAC "next"-->  CK[n+2] ...     (one-way)
      |
      | HMAC(CK[i], "enc")
      v
   EK[i] = AES-256-GCM key for record i ONLY
```

After writing record *i* the host computes `CK[i+1]`, saves it (atomic rename + fsync) and
the previous value is gone. `state.key` therefore only ever holds the *current* chain key.
An attacker who steals the host later can derive keys for **future** records but has no way
to go backwards, so he can neither **decrypt** nor **re-forge** records already written. The
verifier, holding the root key, re-derives the chain sequentially. Each record uses its own
key, which also removes the usual random-IV (2^32 records per key) concern. Rotation starts a
new epoch from a new root key; nothing from the old epoch is left on the host.

### Truncation protection

* **Anchor** (`anchor.mac`): after each record the writer stores `seq:hash:MAC`, where the
  MAC key is derived from that record's chain key. Verification fails if the log is shorter
  than the anchor, the anchor is missing, malformed, or doesn't match the record. Without
  the chain key for record *i*, an attacker cannot forge an anchor for it.
* **Checkpoint** (`checkpoint` / `verify --expect SEQ:HASH`): the same head published
  *outside* the host. It catches what no local data can: a complete rollback of log +
  anchor + key state to an older, self-consistent backup (see demo, Attack E).
* **Crash safety:** a crash between "record written" and "anchor/state updated" is detected
  and repaired by the next writer; a state/log mismatch it cannot explain is refused.

### Roles (least privilege, deny by default)

| Role | Write | Read | Verify / checkpoint | Manage users | Rotate key |
|---|:-:|:-:|:-:|:-:|:-:|
| Logger  | yes | | | | |
| Auditor | | yes | yes | | |
| Admin   | | | yes | yes | yes |

Admin cannot read log contents (separation of duties). Authentication failures, denials,
reads, verifications and tamper detections are written to the encrypted log. `verify` scans
before it records itself, so checking can never repair tamper evidence; `read` records the
access before any plaintext is released and refuses if it cannot be recorded.

## Other security measures

* No hard-coded keys; key/state/user files are 0600, opened `O_NOFOLLOW`, and refused if
  accessible by group/other. Key material is wiped from memory after use.
* Tokens: random 256-bit, stored only as salted PBKDF2-HMAC-SHA256 hashes, compared in
  constant time; unknown users cost the same work as known ones.
* Log injection: control characters are escaped; actor/user names are `[A-Za-z0-9_.-]{1,32}`;
  the record parser is strict about field count, shapes and lengths.
* `flock` serializes writers (tested with 4 concurrent processes). For OS-enforced
  append-only run `sudo chattr +a host/securelog.enc`. Built with stack protector, PIE, RELRO.
* Fails closed: tampered logs release no plaintext; a state/log mismatch stops appends.

## Limitations (what is still NOT solved)

* **Compromise window.** Forward security protects records written *before* the host was
  compromised. An attacker holding `state.key` can read nothing old, but can forge records
  from the moment of compromise onward (including re-writing the tail after it) until a
  checkpoint or an uncompromised verifier covers them. Publish checkpoints often: a
  checkpoint only vouches for records up to its sequence number.
* **Root key placement is the crux.** The guarantees above hold only if the root key is
  genuinely off the logging host. With the default single-directory layout, an attacker who
  owns the host owns the root key too and can re-derive everything. A KMS/HSM or split
  custody of the root key would harden this further (not implemented).
* **Rollback needs an external anchor.** A full restore of an old host is self-consistent;
  only a checkpoint stored elsewhere exposes it.
* **Confidentiality of the root key holder:** whoever has the root key can decrypt the
  whole log. Keep it with auditors only.
* **Performance:** `append` only reads the log tail (O(1)); `read`/`verify` scan the whole
  file and re-derive the chain from the epoch start. Fine for a mini-project; segment files
  or periodic escrowed chain keys would give random access.
* **Bootstrap:** `init` creates the first admin without authentication (nothing exists
  yet); protect the host during setup and store the printed token securely.
