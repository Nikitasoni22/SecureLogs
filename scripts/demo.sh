#!/usr/bin/env bash
# End-to-end demo: encrypted logging, Zero Trust denials, forward security,
# tamper detection (including tail truncation), key rotation, external checkpoints.
set -u
cd "$(dirname "$0")/.."
BIN=./build/securelog
WORK="$(mktemp -d /tmp/securelog_demo_XXXXXX)"
DIR="$WORK/host"            # the LOGGING HOST
OFF="$WORK/offhost"         # media that is NOT on the logging host (root key, checkpoints)
KEYS="$OFF/root.keys"
mkdir -p "$OFF"; chmod 700 "$OFF"
export SECURELOG_PBKDF2_ITERS=20000   # quicker demo; default is 210000
trap 'rm -rf "$WORK"' EXIT

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
as()  { local u=$1 t=$2; shift 2; SECURELOG_USER=$u SECURELOG_TOKEN=$t "$BIN" "$@"; }
snapshot() { rm -rf "$WORK/good"; cp -a "$DIR" "$WORK/good"; }
restore()  { rm -rf "$DIR"; cp -a "$WORK/good" "$DIR"; }
tamper()   { python3 - "$@"; }

say "1. Initialise. The ROOT key is created straight onto off-host media (--keys)"
ADMIN_TOKEN=$($BIN init --dir "$DIR" --keys "$KEYS" --admin root | sed -n 's/^ADMIN_TOKEN=//p')
echo "   logging host holds:"; ls -l "$DIR" | sed 's/^/   /'
echo "   off-host media holds:"; ls -l "$OFF" | sed 's/^/   /'

say "2. Admin creates a logger and an auditor (least privilege)"
LOG_TOKEN=$(as root "$ADMIN_TOKEN" adduser --dir "$DIR" --keys "$KEYS" --name alice --role logger | sed -n 's/^TOKEN=//p')
AUD_TOKEN=$(as root "$ADMIN_TOKEN" adduser --dir "$DIR" --keys "$KEYS" --name bob   --role auditor | sed -n 's/^TOKEN=//p')

say "3. Logger writes events - WITHOUT access to the root key (sensitive data on purpose)"
as alice "$LOG_TOKEN" log --dir "$DIR" --severity INFO     --message "user=jdoe logged in from 10.0.0.7"
as alice "$LOG_TOKEN" log --dir "$DIR" --severity WARN     --message "password reset token=abc123 issued"
as alice "$LOG_TOKEN" log --dir "$DIR" --severity CRITICAL --message "root login attempt blocked"
echo "   raw file on disk (plaintext is NOT visible):"
tail -n 2 "$DIR/securelog.enc" | cut -c1-150 | sed 's/^/   /'
grep -c "abc123" "$DIR/securelog.enc" | sed 's/^/   occurrences of "abc123" in file: /'

say "4. FORWARD SECURITY: the host's key state is overwritten after every record"
echo "   state.key now : $(cut -c1-40 "$DIR/state.key")..."
as alice "$LOG_TOKEN" log --dir "$DIR" --severity INFO --message "another event"
echo "   state.key next: $(cut -c1-40 "$DIR/state.key")...   (one-way ratchet; old key is gone)"

say "5. Zero Trust: wrong roles and bad credentials are refused"
as alice "$LOG_TOKEN" read   --dir "$DIR" --keys "$KEYS"; echo "   -> logger read   exit=$?"
as bob   "$AUD_TOKEN" log    --dir "$DIR" --severity INFO --message x; echo "   -> auditor write exit=$?"
as root  "$ADMIN_TOKEN" read --dir "$DIR" --keys "$KEYS"; echo "   -> admin read    exit=$?"
as bob   "wrong-token" read  --dir "$DIR" --keys "$KEYS"; echo "   -> bad token     exit=$?"

say "6. Auditor (holding the root key) reads: decrypted, in order, with the audit trail"
as bob "$AUD_TOKEN" read --dir "$DIR" --keys "$KEYS"

say "7. Without the root key nobody on the logging host can verify or decrypt"
as bob "$AUD_TOKEN" read --dir "$DIR"; echo "   -> read without --keys exit=$?"

cp -a "$DIR" "$WORK/backup"     # a backup of the whole host, as an attacker might hold one

say "8. Key rotation starts a new epoch (old records stay readable)"
as root "$ADMIN_TOKEN" rotate --dir "$DIR" --keys "$KEYS"
as alice "$LOG_TOKEN" log --dir "$DIR" --severity INFO --message "event written under the new key"
as bob "$AUD_TOKEN" verify --dir "$DIR" --keys "$KEYS"

say "9. Auditor publishes a CHECKPOINT off-host (e.g. WORM storage / SIEM)"
CP=$(as bob "$AUD_TOKEN" checkpoint --dir "$DIR" --keys "$KEYS" | sed -n 's/^CHECKPOINT=//p')
echo "$CP" >> "$OFF/checkpoints.txt"; echo "   stored: ${CP:0:48}..."
as alice "$LOG_TOKEN" log --dir "$DIR" --severity INFO --message "activity after the checkpoint"
snapshot

say "ATTACK A. Flip one hex digit of a ciphertext"
tamper "$DIR/securelog.enc" <<'PY'
import sys
p = sys.argv[1]; L = open(p).read().split("\n"); f = L[2].split("|")
f[7] = ("1" if f[7][0] == "0" else "0") + f[7][1:]; L[2] = "|".join(f)
open(p, "w").write("\n".join(L))
PY
as bob "$AUD_TOKEN" verify --dir "$DIR" --keys "$KEYS"; echo "   -> verify exit=$? (non-zero = tamper detected)"
as bob "$AUD_TOKEN" read   --dir "$DIR" --keys "$KEYS"; echo "   -> read   exit=$? (no plaintext released)"
restore

say "ATTACK B. Delete a record from the middle"
tamper "$DIR/securelog.enc" <<'PY'
import sys
p = sys.argv[1]; L = open(p).read().split("\n"); del L[1]
open(p, "w").write("\n".join(L))
PY
as bob "$AUD_TOKEN" verify --dir "$DIR" --keys "$KEYS"; echo "   -> verify exit=$?"
restore

say "ATTACK C. TAIL TRUNCATION: silently cut the last 3 records (the old blind spot)"
tamper "$DIR/securelog.enc" <<'PY'
import sys
p = sys.argv[1]; L = open(p).read().split("\n")      # last element is "" (trailing newline)
open(p, "w").write("\n".join(L[:-4]) + "\n")
PY
as bob "$AUD_TOKEN" verify --dir "$DIR" --keys "$KEYS"; echo "   -> verify exit=$?"
restore

say "ATTACK D. Truncate AND delete the anchor file"
tamper "$DIR/securelog.enc" <<'PY'
import sys
p = sys.argv[1]; L = open(p).read().split("\n")
open(p, "w").write("\n".join(L[:-4]) + "\n")
PY
rm -f "$DIR/anchor.mac"
as bob "$AUD_TOKEN" verify --dir "$DIR" --keys "$KEYS"; echo "   -> verify exit=$?"
restore

say "ATTACK E. Total rollback: attacker restores the WHOLE host (log + anchor + key state) from an old backup"
rm -rf "$DIR"; cp -a "$WORK/backup" "$DIR"
echo "   the old host is self-consistent, so a local check alone is satisfied:"
as bob "$AUD_TOKEN" verify --dir "$DIR" --keys "$KEYS"
echo "   ...but the off-host checkpoint published in step 9 exposes the rollback:"
as bob "$AUD_TOKEN" verify --dir "$DIR" --keys "$KEYS" --expect "$(tail -n 1 "$OFF/checkpoints.txt")"
echo "   -> exit=$?"
restore
echo "   (the real, untouched host still satisfies its checkpoint:)"
as bob "$AUD_TOKEN" verify --dir "$DIR" --keys "$KEYS" --expect "$(tail -n 1 "$OFF/checkpoints.txt")"
