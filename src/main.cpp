// main.cpp - command line front end for the secure logging module.
//
// Credentials are taken from the environment (never from argv, which is visible
// to other local users through the process list):
//     SECURELOG_USER=<name>  SECURELOG_TOKEN=<token>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include "securelog.hpp"

using namespace securelog;

namespace {

void usage() {
    std::fputs(
        "Usage: securelog <command> --dir DIR [--keys ROOT_KEY_FILE] [options]\n"
        "\n"
        "Commands:\n"
        "  init    --admin NAME                       create store + first admin (prints token once)\n"
        "  adduser --name NAME --role ROLE            [admin] ROLE = logger|auditor|admin\n"
        "  log     --severity SEV --message TEXT      [logger] SEV = DEBUG|INFO|WARN|ERROR|CRITICAL\n"
        "  read                                       [auditor] verify, then print decrypted log\n"
        "  verify  [--expect SEQ:HASH]                [auditor|admin] verify tags, chain, anchor;\n"
        "                                             --expect also checks an off-host checkpoint\n"
        "  checkpoint                                 [auditor|admin] verify, then print SEQ:HASH to\n"
        "                                             store OFF the logging host (WORM, SIEM, ...)\n"
        "  rotate                                     [admin] start a new key epoch\n"
        "\n"
        "--keys points at the root key file (default DIR/keys.db). For forward security keep\n"
        "it on media that is NOT on the logging host and pass it only to verify/read/rotate.\n"
        "Writers (log) never need it.\n"
        "\n"
        "Authenticate with environment variables SECURELOG_USER and SECURELOG_TOKEN.\n",
        stderr);
}

int exit_code(Status s) { return static_cast<int>(s); }

bool parse_opts(int argc, char** argv, int start, std::map<std::string, std::string>& o) {
    for (int i = start; i < argc; ++i) {
        std::string a = argv[i];
        if (a.rfind("--", 0) != 0 || i + 1 >= argc) return false;
        o[a.substr(2)] = argv[++i];
    }
    return true;
}

Credentials creds_from_env() {
    Credentials c;
    const char* u = std::getenv("SECURELOG_USER");
    const char* t = std::getenv("SECURELOG_TOKEN");
    if (u) c.user = u;
    if (t) c.token = t;
    return c;
}

int fail(Status s) {
    // Generic messages only: never echo secrets or distinguish "no such user"
    // from "wrong token".
    std::fprintf(stderr, "securelog: %s\n", to_string(s));
    return exit_code(s);
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        usage();
        return 64;
    }
    const std::string cmd = argv[1];
    std::map<std::string, std::string> opt;
    if (!parse_opts(argc, argv, 2, opt) || !opt.count("dir")) {
        usage();
        return 64;
    }

    Config cfg;
    cfg.dir = opt["dir"];
    if (opt.count("keys")) cfg.keys_file = opt["keys"];
    if (const char* it = std::getenv("SECURELOG_PBKDF2_ITERS")) {
        long v = std::strtol(it, nullptr, 10);
        if (v >= 1000 && v <= 10000000) cfg.pbkdf2_iters = static_cast<std::uint32_t>(v);
    }
    SecureLogger logger(cfg);

    if (cmd == "init") {
        if (!opt.count("admin")) { usage(); return 64; }
        std::string token;
        Status s = logger.init(opt["admin"], token);
        if (s != Status::Ok) return fail(s);
        std::printf("Initialized secure log store in %s\n", cfg.dir.c_str());
        std::printf("ADMIN_TOKEN=%s\n", token.c_str());
        std::puts("Store this token now; it cannot be recovered.");
        return 0;
    }

    const Credentials who = creds_from_env();

    if (cmd == "adduser") {
        Role role;
        if (!opt.count("name") || !opt.count("role") || !parse_role(opt["role"], role)) {
            usage();
            return 64;
        }
        std::string token;
        Status s = logger.add_user(who, opt["name"], role, token);
        if (s != Status::Ok) return fail(s);
        std::printf("User %s (%s) created\nTOKEN=%s\n", opt["name"].c_str(), to_string(role),
                    token.c_str());
        return 0;
    }
    if (cmd == "log") {
        Severity sev;
        if (!opt.count("severity") || !opt.count("message") ||
            !parse_severity(opt["severity"], sev)) {
            usage();
            return 64;
        }
        Status s = logger.append(who, sev, opt["message"]);
        if (s != Status::Ok) return fail(s);
        return 0;
    }
    if (cmd == "read") {
        std::vector<Entry> entries;
        VerifyReport rep;
        Status s = logger.read(who, entries, &rep);
        if (s == Status::TamperDetected) {
            std::fprintf(stderr, "securelog: TAMPERING DETECTED at record %llu: %s\n",
                         static_cast<unsigned long long>(rep.bad_seq), rep.reason.c_str());
            return exit_code(s);
        }
        if (s != Status::Ok) return fail(s);
        for (const auto& e : entries)
            std::printf("%llu | %s | %-8s | %-16s | %s\n", static_cast<unsigned long long>(e.seq),
                        e.timestamp.c_str(), to_string(e.severity), e.actor.c_str(),
                        e.message.c_str());
        return 0;
    }
    if (cmd == "verify") {
        Checkpoint cp;
        const bool have_cp = opt.count("expect") != 0;
        if (have_cp && !parse_checkpoint(opt["expect"], cp)) {
            std::fputs("securelog: --expect must look like SEQ:64-hex-hash\n", stderr);
            return 64;
        }
        VerifyReport rep;
        Status s = logger.verify(who, rep, have_cp ? &cp : nullptr);
        if (s == Status::TamperDetected) {
            std::fprintf(stderr, "securelog: TAMPERING DETECTED at record %llu: %s\n",
                         static_cast<unsigned long long>(rep.bad_seq), rep.reason.c_str());
            return exit_code(s);
        }
        if (s != Status::Ok) return fail(s);
        std::printf("OK: %llu records verified (tags, hash chain, sequence, anchor%s)\n",
                    static_cast<unsigned long long>(rep.records),
                    have_cp ? ", external checkpoint" : "");
        return 0;
    }
    if (cmd == "checkpoint") {
        Checkpoint cp;
        VerifyReport rep;
        Status s = logger.checkpoint(who, cp);
        if (s != Status::Ok) return fail(s);
        std::printf("CHECKPOINT=%s\n", to_string(cp).c_str());
        return 0;
    }
    if (cmd == "rotate") {
        std::uint32_t id = 0;
        Status s = logger.rotate_key(who, &id);
        if (s != Status::Ok) return fail(s);
        std::printf("Rotated: new active key id = %u\n", id);
        return 0;
    }
    usage();
    return 64;
}
