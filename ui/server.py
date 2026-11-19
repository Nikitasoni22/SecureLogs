#!/usr/bin/env python3
"""Local demo dashboard for securelog.

Runs the REAL ./build/securelog binary (nothing is simulated). Standard library only.
    python3 ui/server.py [--port 8080]
then open http://127.0.0.1:8080

Demo-only convenience: the server remembers the three demo users' tokens so the browser
can "log in as" them with a dropdown. The attack buttons edit files on disk the way an
attacker with filesystem access would.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN = os.path.join(ROOT, "build", "securelog")
DATA = os.path.join(ROOT, "ui", "demo_data")
HOST = os.path.join(DATA, "host")            # the logging host
OFF = os.path.join(DATA, "offhost")          # root key + checkpoints live here
KEYS = os.path.join(OFF, "root.keys")
SNAP_OLD = os.path.join(DATA, "snapshot_old")        # attacker's old backup (rollback)
SNAP_PRE = os.path.join(DATA, "snapshot_pre_attack")  # auto-saved before each attack
LOG = os.path.join(HOST, "securelog.enc")

ROLE = {"root": "admin", "alice": "logger", "bob": "auditor"}
TOKENS = {}
CHECKPOINTS = []
CONSOLE = []
ENV_ITERS = "20000"  # quick demo; library default is 210000

EXIT_NAMES = {0: "ok", 1: "authentication failed", 2: "access denied", 3: "invalid input",
              4: "i/o error", 5: "crypto error", 6: "TAMPERING DETECTED", 7: "key error",
              8: "format error", 64: "usage"}


def run_cli(cmd, user=None, extra=None, use_keys=True):
    args = [BIN, cmd, "--dir", HOST]
    if use_keys:
        args += ["--keys", KEYS]
    args += extra or []
    env = dict(os.environ, SECURELOG_PBKDF2_ITERS=ENV_ITERS)
    if user is not None:
        env["SECURELOG_USER"] = user
        env["SECURELOG_TOKEN"] = TOKENS.get(user, "wrong-token-" + user)
    p = subprocess.run(args, capture_output=True, text=True, env=env, timeout=60)
    shown = " ".join(
        [cmd] + [a if not a.startswith("--") or True else a for a in (extra or [])])
    res = {"code": p.returncode, "meaning": EXIT_NAMES.get(p.returncode, "?"),
           "stdout": p.stdout, "stderr": p.stderr.strip(), "as": user, "cmd": shown}
    msg = p.stderr.strip() or ("" if cmd == "read" else (p.stdout.strip().splitlines() or [""])[-1])
    CONSOLE.append({"as": user, "cmd": shown, "code": p.returncode,
                    "meaning": res["meaning"], "msg": msg})
    del CONSOLE[:-60]
    return res


def reset():
    shutil.rmtree(DATA, ignore_errors=True)
    os.makedirs(OFF, mode=0o700)
    TOKENS.clear()
    CHECKPOINTS.clear()
    CONSOLE.clear()
    env = dict(os.environ, SECURELOG_PBKDF2_ITERS=ENV_ITERS)
    out = subprocess.run([BIN, "init", "--dir", HOST, "--keys", KEYS, "--admin", "root"],
                         capture_output=True, text=True, env=env)
    for line in out.stdout.splitlines():
        if line.startswith("ADMIN_TOKEN="):
            TOKENS["root"] = line.split("=", 1)[1]
    for name, role in (("alice", "logger"), ("bob", "auditor")):
        r = run_cli("adduser", "root", ["--name", name, "--role", role])
        for line in r["stdout"].splitlines():
            if line.startswith("TOKEN="):
                TOKENS[name] = line.split("=", 1)[1]
    return {"ok": len(TOKENS) == 3}


def parse_raw():
    rows = []
    if not os.path.exists(LOG):
        return rows
    with open(LOG, "r", errors="replace") as f:
        for i, line in enumerate(f.read().split("\n")):
            if line == "" and i > 0:
                continue
            p = line.split("|")
            if len(p) == 10:
                rows.append({"n": i + 1, "magic": p[0], "seq": p[1], "ts": p[2], "sev": p[3],
                             "actor": p[4], "key_id": p[5], "iv": p[6], "ct": p[7],
                             "tag": p[8], "prev": p[9], "ok": True})
            else:
                rows.append({"n": i + 1, "raw": line[:200], "ok": False})
    return rows


def read_file(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def state():
    st = read_file(os.path.join(HOST, "state.key"))
    anchor = read_file(os.path.join(HOST, "anchor.mac"))
    st_parts = st.split(":") if st else None
    return {
        "host_files": sorted(os.listdir(HOST)) if os.path.isdir(HOST) else [],
        "offhost_files": sorted(os.listdir(OFF)) if os.path.isdir(OFF) else [],
        "state": {"next_seq": st_parts[0], "key_id": st_parts[1], "chain_key": st_parts[2]}
        if st_parts and len(st_parts) == 3 else None,
        "anchor": anchor,
        "checkpoints": CHECKPOINTS,
        "has_old_snapshot": os.path.isdir(SNAP_OLD),
        "has_pre_attack": os.path.isdir(SNAP_PRE),
        "console": CONSOLE,
        "users": [{"name": n, "role": r} for n, r in ROLE.items()],
    }


def copy_host(dst):
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(HOST, dst)


def restore_host(src):
    shutil.rmtree(HOST, ignore_errors=True)
    shutil.copytree(src, HOST)


def read_lines():
    with open(LOG, "r") as f:
        return f.read().split("\n")[:-1]


def write_lines(lines):
    with open(LOG, "w") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))


def attack(kind, params):
    copy_host(SNAP_PRE)
    lines = read_lines()
    n = len(lines)
    idx = int(params.get("record", 2)) - 1
    desc = ""
    if kind != "rollback" and n < 3:
        return {"ok": False, "msg": "Write a few log entries first (need at least 3)."}
    idx = max(0, min(idx, n - 1))
    if kind == "flip":
        f = lines[idx].split("|")
        f[7] = ("1" if f[7][:1] == "0" else "0") + f[7][1:]
        lines[idx] = "|".join(f)
        write_lines(lines)
        desc = f"Flipped one hex digit of the ciphertext of record {idx + 1}."
    elif kind == "severity":
        f = lines[idx].split("|")
        f[3] = "DEBUG" if f[3] != "DEBUG" else "CRITICAL"
        lines[idx] = "|".join(f)
        write_lines(lines)
        desc = f"Changed the (plaintext) severity of record {idx + 1}. It is authenticated as AAD."
    elif kind == "delete":
        del lines[idx]
        write_lines(lines)
        desc = f"Deleted record {idx + 1} from the file."
    elif kind == "swap":
        if idx + 1 >= n:
            idx = n - 2
        lines[idx], lines[idx + 1] = lines[idx + 1], lines[idx]
        write_lines(lines)
        desc = f"Swapped records {idx + 1} and {idx + 2}."
    elif kind == "truncate":
        k = 3
        write_lines(lines[:-k])
        desc = f"Silently cut the last {k} records off the end of the log."
    elif kind == "truncate_anchor":
        write_lines(lines[:-3])
        try:
            os.remove(os.path.join(HOST, "anchor.mac"))
        except OSError:
            pass
        desc = "Cut the last 3 records AND deleted anchor.mac."
    elif kind == "rollback":
        if not os.path.isdir(SNAP_OLD):
            return {"ok": False, "msg": "Take the 'old backup' first (step in the Attacks panel)."}
        restore_host(SNAP_OLD)
        desc = "Restored the ENTIRE host (log + anchor + key state) from the old backup."
    else:
        return {"ok": False, "msg": "unknown attack"}
    return {"ok": True, "msg": desc}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj, code=200, ctype="application/json"):
        body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            with open(os.path.join(ROOT, "ui", "index.html"), "rb") as f:
                return self._send(f.read(), ctype="text/html; charset=utf-8")
        if self.path == "/api/raw":
            return self._send({"rows": parse_raw(), **state()})
        if self.path == "/api/state":
            return self._send(state())
        self._send({"error": "not found"}, 404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
        except ValueError:
            return self._send({"error": "bad json"}, 400)
        p = self.path
        u = body.get("user")
        try:
            if p == "/api/reset":
                return self._send(reset())
            if p == "/api/log":
                return self._send(run_cli("log", u, ["--severity", body.get("severity", "INFO"),
                                                     "--message", body.get("message", "")],
                                          use_keys=False))
            if p == "/api/read":
                r = run_cli("read", u)
                entries = []
                for line in r["stdout"].splitlines():
                    parts = [x.strip() for x in line.split("|", 4)]
                    if len(parts) == 5:
                        entries.append(dict(zip(("seq", "ts", "sev", "actor", "msg"), parts)))
                r["entries"] = entries
                return self._send(r)
            if p == "/api/verify":
                extra = []
                if body.get("expect"):
                    extra = ["--expect", body["expect"]]
                return self._send(run_cli("verify", u, extra))
            if p == "/api/checkpoint":
                r = run_cli("checkpoint", u)
                for line in r["stdout"].splitlines():
                    if line.startswith("CHECKPOINT="):
                        CHECKPOINTS.append(line.split("=", 1)[1])
                return self._send(r)
            if p == "/api/rotate":
                return self._send(run_cli("rotate", u))
            if p == "/api/attack":
                return self._send(attack(body.get("kind"), body))
            if p == "/api/restore":
                if os.path.isdir(SNAP_PRE):
                    restore_host(SNAP_PRE)
                    return self._send({"ok": True, "msg": "Restored the state from just before the last attack."})
                return self._send({"ok": False, "msg": "Nothing to restore."})
            if p == "/api/backup":
                copy_host(SNAP_OLD)
                return self._send({"ok": True, "msg": "Attacker took a full backup of the host (log, anchor, key state)."})
        except Exception as e:  # keep the demo alive
            return self._send({"error": str(e)}, 500)
        self._send({"error": "not found"}, 404)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080)
    a = ap.parse_args()
    if not os.path.exists(BIN):
        print("Building securelog first...")
        subprocess.check_call(["make", "-C", ROOT, "all"])
    reset()
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    print(f"securelog demo dashboard: http://127.0.0.1:{a.port}   (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
