// SPDX-License-Identifier: AGPL-3.0-only
#include "wutong/core.hpp"
#include "wutong/sqlite3_compat.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>
#if defined(__unix__) || defined(__APPLE__)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace wutong {
namespace {

struct Statement {
    sqlite3* db{};
    sqlite3_stmt* stmt{};
    Statement(sqlite3* db_, const char* sql) : db(db_) {
        if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK)
            throw std::runtime_error(sqlite3_errmsg(db_));
    }
    ~Statement() { sqlite3_finalize(stmt); }
    void bind(int i, std::string_view val) {
        if (sqlite3_bind_text(stmt, i, val.data(), static_cast<int>(val.size()), SQLITE_TRANSIENT) != SQLITE_OK)
            throw std::runtime_error("bind failed");
    }
    void bind_blob(int i, std::string_view val) {
        if (sqlite3_bind_blob(stmt, i, val.data(), static_cast<int>(val.size()), SQLITE_TRANSIENT) != SQLITE_OK)
            throw std::runtime_error("bind blob failed");
    }
    int step() { return sqlite3_step(stmt); }
    std::string col(int i) const {
        const auto *p = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i));
        return p ? std::string(p, sqlite3_column_bytes(stmt, i)) : "";
    }
    std::string blob(int i) const {
        const auto *p = static_cast<const char*>(sqlite3_column_blob(stmt, i));
        return p ? std::string(p, sqlite3_column_bytes(stmt, i)) : "";
    }
};

void must_done(Statement &s) {
    if (s.step() != SQLITE_DONE)
        throw std::runtime_error(std::string("SQLite write failed: ") + sqlite3_errmsg(s.db));
}

std::string now_utc() {
    using namespace std::chrono;
    auto time = floor<seconds>(system_clock::now());
    return std::to_string(time.time_since_epoch().count());
}

std::string file_path(const std::filesystem::path &p) {
    return std::filesystem::absolute(p).lexically_normal().string();
}

void fsync_dir_posix(const std::filesystem::path &dir) {
#if defined(__unix__) || defined(__APPLE__)
    int fd = ::open(dir.string().c_str(), O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        (void)::fsync(fd);
        ::close(fd);
    }
#else
    (void)dir;
#endif
}

void write_and_fsync_file(const std::filesystem::path &tmp, std::string_view content) {
#if defined(__unix__) || defined(__APPLE__)
    int fd = ::open(tmp.string().c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (fd < 0) throw std::runtime_error("temp open failed");
    size_t written = 0;
    while (written < content.size()) {
        ssize_t n = ::write(fd, content.data() + written, content.size() - written);
        if (n <= 0) {
            ::close(fd);
            std::error_code ec;
            std::filesystem::remove(tmp, ec);
            throw std::runtime_error("temp write failed");
        }
        written += static_cast<size_t>(n);
    }
    if (::fsync(fd) != 0) {
        ::close(fd);
        std::error_code ec;
        std::filesystem::remove(tmp, ec);
        throw std::runtime_error("temp fsync failed");
    }
    ::close(fd);
    fsync_dir_posix(tmp.parent_path());
#else
    std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("temp write failed");
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    out.flush();
    if (!out) throw std::runtime_error("temp flush failed");
#endif
}

} // namespace

std::string uuid_v7_urn() {
    uint8_t b[16];
    if (RAND_bytes(b, sizeof(b)) != 1) throw std::runtime_error("secure random failed");
    using namespace std::chrono;
    const auto ms = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    for (int i = 0; i < 6; i++) b[i] = static_cast<uint8_t>((static_cast<uint64_t>(ms) >> (8 * (5 - i))) & 0xff);
    b[6] = static_cast<uint8_t>((b[6] & 0x0f) | 0x70);
    b[8] = static_cast<uint8_t>((b[8] & 0x3f) | 0x80);
    std::ostringstream out;
    out << "urn:uuid:" << std::hex << std::setfill('0');
    for (int i = 0; i < 16; i++) {
        out << std::setw(2) << int(b[i]);
        if (i == 3 || i == 5 || i == 7 || i == 9) out << '-';
    }
    return out.str();
}

std::string sha256_hex(std::string_view data) {
    unsigned char d[32];
    unsigned int len = 0;
    auto *c = EVP_MD_CTX_new();
    if (!c) throw std::runtime_error("EVP allocation");
    bool ok = EVP_DigestInit_ex(c, EVP_sha256(), nullptr) == 1 &&
              EVP_DigestUpdate(c, data.data(), data.size()) == 1 &&
              EVP_DigestFinal_ex(c, d, &len) == 1;
    EVP_MD_CTX_free(c);
    if (!ok || len != 32) throw std::runtime_error("SHA256 failed");
    std::ostringstream s;
    s << std::hex << std::setfill('0');
    for (auto b : d) s << std::setw(2) << int(b);
    return s.str();
}

std::string read_bytes(const std::filesystem::path &p) {
    if (std::filesystem::is_symlink(p))
        throw std::runtime_error("ERR_SYMLINK_OR_TRAVERSAL: symlink rejected");
    std::ifstream in(p, std::ios::binary);
    if (!in) throw std::runtime_error("open file failed");
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

Store::Store(const std::filesystem::path &db_path) {
    if (sqlite3_open(db_path.string().c_str(), &db_) != SQLITE_OK)
        throw std::runtime_error("open db failed");
    exec("PRAGMA foreign_keys=ON; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=4000;");
    exec(R"SQL(
CREATE TABLE IF NOT EXISTS principals(id TEXT PRIMARY KEY, kind TEXT NOT NULL, label TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS documents(object_id TEXT PRIMARY KEY,path TEXT UNIQUE NOT NULL,owner_id TEXT NOT NULL REFERENCES principals(id),media_type TEXT NOT NULL,head_digest TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS revisions(id TEXT PRIMARY KEY,object_id TEXT NOT NULL REFERENCES documents(object_id),digest TEXT NOT NULL,actor TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS grants(id TEXT PRIMARY KEY,issuer TEXT NOT NULL,subject TEXT NOT NULL,object_id TEXT NOT NULL,action TEXT NOT NULL,UNIQUE(issuer,subject,object_id,action));
CREATE TABLE IF NOT EXISTS proposals(id TEXT PRIMARY KEY,object_id TEXT NOT NULL REFERENCES documents(object_id),agent TEXT NOT NULL,base_digest TEXT NOT NULL,replacement BLOB NOT NULL,status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS write_intents(id TEXT PRIMARY KEY,proposal_id TEXT NOT NULL,object_id TEXT NOT NULL,reviewer TEXT NOT NULL,old_digest TEXT NOT NULL,new_digest TEXT NOT NULL,tmp_path TEXT NOT NULL,status TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS relations(id TEXT PRIMARY KEY,src_id TEXT NOT NULL REFERENCES documents(object_id),dst_id TEXT NOT NULL,predicate TEXT NOT NULL,actor TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,actor TEXT NOT NULL,action TEXT NOT NULL,subject TEXT NOT NULL,result TEXT NOT NULL,created_at TEXT NOT NULL);
)SQL");
}

Store::~Store() {
    if (db_) sqlite3_close(db_);
}

void Store::exec(std::string_view sql) const {
    char *err = nullptr;
    std::string s(sql);
    if (sqlite3_exec(db_, s.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
        std::string e = err ? err : "SQL failure";
        sqlite3_free(err);
        throw std::runtime_error(e);
    }
}

bool Store::principal_exists(std::string_view id) const {
    Statement s(db_, "SELECT id FROM principals WHERE id=?");
    s.bind(1, id);
    return s.step() == SQLITE_ROW;
}

std::string Store::create_principal(std::string_view kind, std::string_view label) {
    if (kind != "human" && kind != "agent" && kind != "organization" && kind != "service" && kind != "device")
        throw std::runtime_error("invalid kind");
    const auto id = uuid_v7_urn();
    Statement s(db_, "INSERT INTO principals VALUES(?,?,?)");
    s.bind(1, id);
    s.bind(2, kind);
    s.bind(3, label);
    must_done(s);
    return id;
}

void Store::add_revision(std::string_view oid, std::string_view digest, std::string_view actor) {
    Statement s(db_, "INSERT INTO revisions VALUES(?,?,?,?,?)");
    auto id = uuid_v7_urn();
    auto now = now_utc();
    s.bind(1, id);
    s.bind(2, oid);
    s.bind(3, digest);
    s.bind(4, actor);
    s.bind(5, now);
    must_done(s);
}

void Store::log_event(std::string_view actor, std::string_view action, std::string_view subject, std::string_view result) {
    Statement s(db_, "INSERT INTO events VALUES(?,?,?,?,?,?)");
    auto id = uuid_v7_urn();
    auto now = now_utc();
    s.bind(1, id);
    s.bind(2, actor);
    s.bind(3, action);
    s.bind(4, subject);
    s.bind(5, result);
    s.bind(6, now);
    must_done(s);
}

Document Store::import_file(const std::filesystem::path &path, std::string_view owner, std::string_view media) {
    if (!principal_exists(owner)) throw std::runtime_error("unknown owner");
    auto abs = file_path(path);
    auto digest = sha256_hex(read_bytes(path));
    {
        Statement q(db_, "SELECT object_id FROM documents WHERE path=?");
        q.bind(1, abs);
        if (q.step() == SQLITE_ROW) {
            auto d = document(q.col(0));
            if (d.head_digest != digest)
                throw std::runtime_error("changed on disk; call refresh_from_disk");
            return d;
        }
    }
    const auto oid = uuid_v7_urn();
    exec("BEGIN IMMEDIATE");
    try {
        Statement s(db_, "INSERT INTO documents VALUES(?,?,?,?,?)");
        s.bind(1, oid);
        s.bind(2, abs);
        s.bind(3, owner);
        s.bind(4, media);
        s.bind(5, digest);
        must_done(s);
        add_revision(oid, digest, owner);
        log_event(owner, "document.import", oid, "ok");
        exec("COMMIT");
    } catch (...) {
        exec("ROLLBACK");
        throw;
    }
    return document(oid);
}

Document Store::document(std::string_view oid) const {
    Statement s(db_, "SELECT object_id,path,owner_id,media_type,head_digest FROM documents WHERE object_id=?");
    s.bind(1, oid);
    if (s.step() != SQLITE_ROW) throw std::runtime_error("object not found");
    return {s.col(0), s.col(1), s.col(2), s.col(3), s.col(4)};
}

std::string Store::refresh_from_disk(std::string_view oid, std::string_view actor) {
    const auto d = document(oid);
    if (actor != d.owner) throw std::runtime_error("refresh restricted to owner in prototype");
    const auto digest = sha256_hex(read_bytes(d.path));
    if (digest == d.head_digest) return digest;
    exec("BEGIN IMMEDIATE");
    try {
        Statement s(db_, "UPDATE documents SET head_digest=? WHERE object_id=?");
        s.bind(1, digest);
        s.bind(2, oid);
        must_done(s);
        add_revision(oid, digest, actor);
        log_event(actor, "document.refresh", oid, "ok");
        exec("COMMIT");
    } catch (...) {
        exec("ROLLBACK");
        throw;
    }
    return digest;
}

void Store::grant_local(std::string_view owner, std::string_view subject, std::string_view oid, std::string_view action) {
    if (document(oid).owner != owner || !principal_exists(subject))
        throw std::runtime_error("not owner or unknown subject");
    Statement s(db_, "INSERT OR IGNORE INTO grants VALUES(?,?,?,?,?)");
    auto id = uuid_v7_urn();
    s.bind(1, id);
    s.bind(2, owner);
    s.bind(3, subject);
    s.bind(4, oid);
    s.bind(5, action);
    must_done(s);
    log_event(owner, "grant.local", oid, "ok");
}

bool Store::can(std::string_view who, std::string_view oid, std::string_view action) const {
    if (document(oid).owner == who) return true;
    Statement s(db_, "SELECT 1 FROM grants WHERE subject=? AND object_id=? AND action=?");
    s.bind(1, who);
    s.bind(2, oid);
    s.bind(3, action);
    return s.step() == SQLITE_ROW;
}

std::string Store::propose_replace(std::string_view agent, std::string_view oid, std::string_view expected, std::string_view replacement) {
    if (!principal_exists(agent) || !can(agent, oid, "document.propose"))
        throw std::runtime_error("no permission: document.propose");
    auto d = document(oid);
    if (d.head_digest != expected) throw std::runtime_error("stale document digest");
    auto id = uuid_v7_urn();
    Statement s(db_, "INSERT INTO proposals VALUES(?,?,?,?,?,?)");
    s.bind(1, id);
    s.bind(2, oid);
    s.bind(3, agent);
    s.bind(4, expected);
    s.bind_blob(5, replacement);
    s.bind(6, "pending");
    must_done(s);
    log_event(agent, "document.propose", oid, "pending");
    return id;
}

void Store::finalize_intent(std::string_view intent_id, std::string_view proposal_id,
                            std::string_view object_id, std::string_view new_digest,
                            std::string_view reviewer) {
    exec("BEGIN IMMEDIATE");
    try {
        Statement up(db_, "UPDATE documents SET head_digest=? WHERE object_id=?");
        up.bind(1, new_digest);
        up.bind(2, object_id);
        must_done(up);
        Statement a(db_, "UPDATE proposals SET status='applied' WHERE id=?");
        a.bind(1, proposal_id);
        must_done(a);
        Statement wi(db_, "UPDATE write_intents SET status='committed' WHERE id=?");
        wi.bind(1, intent_id);
        must_done(wi);
        add_revision(object_id, new_digest, reviewer);
        log_event(reviewer, "document.apply", object_id, "ok");
        exec("COMMIT");
    } catch (...) {
        exec("ROLLBACK");
        throw;
    }
}

void Store::approve_apply(std::string_view reviewer, std::string_view pid, CrashPoint crash_at) {
    Statement p(db_, "SELECT object_id,base_digest,replacement,status FROM proposals WHERE id=?");
    p.bind(1, pid);
    if (p.step() != SQLITE_ROW) throw std::runtime_error("proposal not found");
    const auto oid = p.col(0), base = p.col(1), content = p.blob(2), status = p.col(3);
    if (status != "pending") throw std::runtime_error("already reviewed");
    const auto d = document(oid);
    if (reviewer != d.owner) throw std::runtime_error("only owner reviews in prototype");
    if (base != d.head_digest || base != sha256_hex(read_bytes(d.path)))
        throw std::runtime_error("conflict: base revision stale");

    const auto intent_id = uuid_v7_urn();
    const auto newhash = sha256_hex(content);
    const auto tmp = std::filesystem::path(d.path + ".wutong-" + intent_id.substr(9) + ".pending");
    write_and_fsync_file(tmp, content);

    exec("BEGIN IMMEDIATE");
    try {
        Statement wi(db_, "INSERT INTO write_intents VALUES(?,?,?,?,?,?,?,?)");
        wi.bind(1, intent_id);
        wi.bind(2, pid);
        wi.bind(3, oid);
        wi.bind(4, reviewer);
        wi.bind(5, base);
        wi.bind(6, newhash);
        wi.bind(7, tmp.string());
        wi.bind(8, "prepared");
        must_done(wi);
        exec("COMMIT");
    } catch (...) {
        exec("ROLLBACK");
        std::error_code ec;
        std::filesystem::remove(tmp, ec);
        throw;
    }

    if (crash_at == CrashPoint::Prepared)
        throw SimulatedCrash("simulated crash after prepared intent");

    if (sha256_hex(read_bytes(d.path)) != base)
        throw std::runtime_error("external file modification after prepare");

    std::filesystem::rename(tmp, d.path);
    fsync_dir_posix(std::filesystem::path(d.path).parent_path());

    if (crash_at == CrashPoint::Replaced)
        throw SimulatedCrash("simulated crash after atomic file replace");

    finalize_intent(intent_id, pid, oid, newhash, reviewer);

    if (crash_at == CrashPoint::Committed)
        throw SimulatedCrash("simulated crash after SQLite commit");
}

std::vector<std::pair<std::string, std::string>> Store::recover_intents() {
    struct Row {
        std::string iid, pid, oid, reviewer, old_d, new_d, tmp_p;
    };
    std::vector<Row> pending;
    {
        Statement q(db_, "SELECT id,proposal_id,object_id,reviewer,old_digest,new_digest,tmp_path FROM write_intents WHERE status='prepared'");
        while (q.step() == SQLITE_ROW) {
            pending.push_back({q.col(0), q.col(1), q.col(2), q.col(3), q.col(4), q.col(5), q.col(6)});
        }
    }
    std::vector<std::pair<std::string, std::string>> out;
    for (const auto &r : pending) {
        auto d = document(r.oid);
        std::filesystem::path doc_p(d.path);
        std::filesystem::path tmp_p(r.tmp_p);
        std::string cur_d = (std::filesystem::exists(doc_p) && !std::filesystem::is_symlink(doc_p))
                            ? sha256_hex(read_bytes(doc_p))
                            : "";
        if (cur_d == r.new_d) {
            finalize_intent(r.iid, r.pid, r.oid, r.new_d, r.reviewer);
            std::error_code ec;
            std::filesystem::remove(tmp_p, ec);
            out.emplace_back(r.iid, "finalized");
            continue;
        }
        if (cur_d == r.old_d && std::filesystem::exists(tmp_p) && !std::filesystem::is_symlink(tmp_p) &&
            sha256_hex(read_bytes(tmp_p)) == r.new_d) {
            std::filesystem::rename(tmp_p, doc_p);
            fsync_dir_posix(doc_p.parent_path());
            finalize_intent(r.iid, r.pid, r.oid, r.new_d, r.reviewer);
            out.emplace_back(r.iid, "rolled-forward");
            continue;
        }
        out.emplace_back(r.iid, "conflict");
    }
    return out;
}

std::string Store::create_relation(std::string_view actor, std::string_view source, std::string_view target, std::string_view predicate) {
    if (!can(actor, source, "relation.create"))
        throw std::runtime_error("not authorized for relation");
    auto id = uuid_v7_urn();
    Statement s(db_, "INSERT INTO relations VALUES(?,?,?,?,?)");
    s.bind(1, id);
    s.bind(2, source);
    s.bind(3, target);
    s.bind(4, predicate);
    s.bind(5, actor);
    must_done(s);
    log_event(actor, "relation.create", source, "ok");
    return id;
}

int Store::revision_count(std::string_view oid) const {
    Statement s(db_, "SELECT COUNT(*) FROM revisions WHERE object_id=?");
    s.bind(1, oid);
    return s.step() == SQLITE_ROW ? sqlite3_column_int(s.stmt, 0) : 0;
}

int Store::event_count() const {
    Statement s(db_, "SELECT COUNT(*) FROM events");
    return s.step() == SQLITE_ROW ? sqlite3_column_int(s.stmt, 0) : 0;
}

bool Store::has_pending_proposal(std::string_view id) const {
    Statement s(db_, "SELECT status FROM proposals WHERE id=?");
    s.bind(1, id);
    return s.step() == SQLITE_ROW && s.col(0) == "pending";
}

// ============================================================================
// Strict JSON Parser, RFC 8785 JCS, RFC 8949 dCBOR & Ed25519 Verifier (C++23)
// ============================================================================
namespace {

std::vector<uint16_t> utf8_to_utf16_units(std::string_view s) {
    std::vector<uint16_t> out;
    size_t i = 0;
    while (i < s.size()) {
        uint8_t c = static_cast<uint8_t>(s[i]);
        uint32_t cp = 0;
        size_t extra = 0;
        uint32_t min_cp = 0;
        if (c < 0x80) {
            cp = c;
            extra = 0;
            min_cp = 0;
        } else if ((c & 0xE0) == 0xC0) {
            cp = c & 0x1F;
            extra = 1;
            min_cp = 0x80;
        } else if ((c & 0xF0) == 0xE0) {
            cp = c & 0x0F;
            extra = 2;
            min_cp = 0x800;
        } else if ((c & 0xF8) == 0xF0) {
            cp = c & 0x07;
            extra = 3;
            min_cp = 0x10000;
        } else {
            throw std::runtime_error("ERR_SCHEMA: invalid UTF-8 lead byte");
        }
        if (i + extra >= s.size())
            throw std::runtime_error("ERR_SCHEMA: truncated UTF-8 sequence");
        for (size_t j = 1; j <= extra; ++j) {
            uint8_t cc = static_cast<uint8_t>(s[i + j]);
            if ((cc & 0xC0) != 0x80)
                throw std::runtime_error("ERR_SCHEMA: invalid UTF-8 continuation byte");
            cp = (cp << 6) | (cc & 0x3F);
        }
        if (cp < min_cp || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
            throw std::runtime_error("ERR_SCHEMA: overlong UTF-8 or surrogate code point");
        i += 1 + extra;
        if (cp <= 0xFFFF) {
            out.push_back(static_cast<uint16_t>(cp));
        } else {
            uint32_t u = cp - 0x10000;
            out.push_back(static_cast<uint16_t>(0xD800 + (u >> 10)));
            out.push_back(static_cast<uint16_t>(0xDC00 + (u & 0x3FF)));
        }
    }
    return out;
}

void append_utf8(std::string &out, uint32_t cp) {
    if (cp >= 0xD800 && cp <= 0xDFFF)
        throw std::runtime_error("ERR_SCHEMA: unpaired surrogate");
    if (cp <= 0x7F) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0x10FFFF) {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        throw std::runtime_error("ERR_SCHEMA: invalid code point");
    }
}

struct Utf16KeyLess {
    bool operator()(const std::string &a, const std::string &b) const {
        return utf8_to_utf16_units(a) < utf8_to_utf16_units(b);
    }
};

struct JsonVal;
using JsonArr = std::vector<JsonVal>;
using JsonObj = std::map<std::string, JsonVal, Utf16KeyLess>;

struct JsonVal {
    std::variant<std::monostate, bool, int64_t, std::string, JsonArr, JsonObj> v;
};

struct Parser {
    std::string_view src;
    size_t pos{0};
    bool allow_unicode_keys{false};

    void skip_ws() {
        while (pos < src.size() && (src[pos] == ' ' || src[pos] == '\t' || src[pos] == '\r' || src[pos] == '\n'))
            ++pos;
    }

    uint16_t parse_hex4() {
        if (pos + 4 > src.size()) throw std::runtime_error("ERR_SCHEMA: truncated \\u escape");
        uint16_t v = 0;
        for (int i = 0; i < 4; ++i) {
            char c = src[pos++];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= (c - '0');
            else if (c >= 'a' && c <= 'f') v |= (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= (c - 'A' + 10);
            else throw std::runtime_error("ERR_SCHEMA: bad hex in \\u escape");
        }
        return v;
    }

    std::string parse_string() {
        if (pos >= src.size() || src[pos] != '"')
            throw std::runtime_error("ERR_SCHEMA: expected '\"'");
        ++pos;
        std::string out;
        while (pos < src.size()) {
            uint8_t c = static_cast<uint8_t>(src[pos]);
            if (c == '"') {
                ++pos;
                (void)utf8_to_utf16_units(out);
                return out;
            }
            if (c < 0x20)
                throw std::runtime_error("ERR_SCHEMA: unescaped control char in string");
            if (c == '\\') {
                ++pos;
                if (pos >= src.size()) throw std::runtime_error("ERR_SCHEMA: trailing backslash");
                char esc = src[pos++];
                switch (esc) {
                    case '"': out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    case '/': out.push_back('/'); break;
                    case 'b': out.push_back('\b'); break;
                    case 'f': out.push_back('\f'); break;
                    case 'n': out.push_back('\n'); break;
                    case 'r': out.push_back('\r'); break;
                    case 't': out.push_back('\t'); break;
                    case 'u': {
                        uint16_t u1 = parse_hex4();
                        if (u1 >= 0xD800 && u1 <= 0xDBFF) {
                            if (pos + 2 > src.size() || src[pos] != '\\' || src[pos + 1] != 'u')
                                throw std::runtime_error("ERR_SCHEMA: unpaired high surrogate");
                            pos += 2;
                            uint16_t u2 = parse_hex4();
                            if (u2 < 0xDC00 || u2 > 0xDFFF)
                                throw std::runtime_error("ERR_SCHEMA: invalid low surrogate");
                            uint32_t cp = 0x10000 + ((static_cast<uint32_t>(u1 - 0xD800) << 10) | (u2 - 0xDC00));
                            append_utf8(out, cp);
                        } else if (u1 >= 0xDC00 && u1 <= 0xDFFF) {
                            throw std::runtime_error("ERR_SCHEMA: unpaired low surrogate");
                        } else {
                            append_utf8(out, u1);
                        }
                        break;
                    }
                    default:
                        throw std::runtime_error("ERR_SCHEMA: invalid escape sequence");
                }
            } else {
                out.push_back(static_cast<char>(c));
                ++pos;
            }
        }
        throw std::runtime_error("ERR_SCHEMA: unterminated string");
    }

    int64_t parse_int() {
        size_t start = pos;
        if (src[pos] == '-') ++pos;
        if (pos >= src.size() || !std::isdigit(static_cast<unsigned char>(src[pos])))
            throw std::runtime_error("ERR_SCHEMA: invalid number");
        if (src[pos] == '0' && pos + 1 < src.size() && std::isdigit(static_cast<unsigned char>(src[pos + 1])))
            throw std::runtime_error("ERR_SCHEMA: leading zero in number");
        while (pos < src.size() && std::isdigit(static_cast<unsigned char>(src[pos]))) ++pos;
        if (pos < src.size() && (src[pos] == '.' || src[pos] == 'e' || src[pos] == 'E'))
            throw std::runtime_error("ERR_SCHEMA: floating numbers not supported by wtp/0.1 JSON profile");
        std::string num_s(src.substr(start, pos - start));
        int64_t val = 0;
        try {
            size_t idx = 0;
            val = std::stoll(num_s, &idx, 10);
            if (idx != num_s.size()) throw std::runtime_error("ERR_SCHEMA: trailing number chars");
        } catch (...) {
            throw std::runtime_error("ERR_SCHEMA: integer overflow");
        }
        constexpr int64_t MAX_SAFE = (1LL << 53) - 1;
        if (val < -MAX_SAFE || val > MAX_SAFE)
            throw std::runtime_error("ERR_SCHEMA: unsafe integer outside IEEE-754 exact range");
        return val;
    }

    JsonVal parse_value(int depth) {
        if (depth > 40) throw std::runtime_error("ERR_SCHEMA: nesting limit exceeded");
        skip_ws();
        if (pos >= src.size()) throw std::runtime_error("ERR_SCHEMA: unexpected EOF");
        char c = src[pos];
        if (c == '"') return JsonVal{parse_string()};
        if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) return JsonVal{parse_int()};
        if (c == 't') {
            if (src.substr(pos, 4) != "true") throw std::runtime_error("ERR_SCHEMA: invalid literal");
            pos += 4;
            return JsonVal{true};
        }
        if (c == 'f') {
            if (src.substr(pos, 5) != "false") throw std::runtime_error("ERR_SCHEMA: invalid literal");
            pos += 5;
            return JsonVal{false};
        }
        if (c == 'n') {
            if (src.substr(pos, 4) != "null") throw std::runtime_error("ERR_SCHEMA: invalid literal");
            pos += 4;
            return JsonVal{std::monostate{}};
        }
        if (c == '[') {
            ++pos;
            skip_ws();
            JsonArr arr;
            if (pos < src.size() && src[pos] == ']') {
                ++pos;
                return JsonVal{std::move(arr)};
            }
            while (true) {
                arr.push_back(parse_value(depth + 1));
                skip_ws();
                if (pos >= src.size()) throw std::runtime_error("ERR_SCHEMA: unterminated array");
                if (src[pos] == ']') {
                    ++pos;
                    break;
                }
                if (src[pos] != ',') throw std::runtime_error("ERR_SCHEMA: expected ',' in array");
                ++pos;
            }
            return JsonVal{std::move(arr)};
        }
        if (c == '{') {
            ++pos;
            skip_ws();
            JsonObj obj;
            if (pos < src.size() && src[pos] == '}') {
                ++pos;
                return JsonVal{std::move(obj)};
            }
            while (true) {
                skip_ws();
                std::string k = parse_string();
                if (!allow_unicode_keys) {
                    if (k.empty()) throw std::runtime_error("ERR_SCHEMA: empty key");
                    for (unsigned char ch : k) {
                        if (ch < 0x21 || ch > 0x7E)
                            throw std::runtime_error("ERR_SCHEMA: non-ASCII member name");
                    }
                }
                skip_ws();
                if (pos >= src.size() || src[pos] != ':')
                    throw std::runtime_error("ERR_SCHEMA: expected ':' after key");
                ++pos;
                JsonVal val = parse_value(depth + 1);
                if (obj.find(k) != obj.end())
                    throw std::runtime_error("ERR_SCHEMA: duplicate key");
                obj.emplace(std::move(k), std::move(val));
                skip_ws();
                if (pos >= src.size()) throw std::runtime_error("ERR_SCHEMA: unterminated object");
                if (src[pos] == '}') {
                    ++pos;
                    break;
                }
                if (src[pos] != ',') throw std::runtime_error("ERR_SCHEMA: expected ',' in object");
                ++pos;
            }
            return JsonVal{std::move(obj)};
        }
        throw std::runtime_error("ERR_SCHEMA: unexpected token");
    }
};

void serialize_jcs_string(std::string &out, std::string_view s) {
    out.push_back('"');
    for (unsigned char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    char buf[7];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    out.push_back('"');
}

void serialize_jcs_value(std::string &out, const JsonVal &val) {
    if (std::holds_alternative<std::monostate>(val.v)) {
        out += "null";
    } else if (std::holds_alternative<bool>(val.v)) {
        out += std::get<bool>(val.v) ? "true" : "false";
    } else if (std::holds_alternative<int64_t>(val.v)) {
        out += std::to_string(std::get<int64_t>(val.v));
    } else if (std::holds_alternative<std::string>(val.v)) {
        serialize_jcs_string(out, std::get<std::string>(val.v));
    } else if (std::holds_alternative<JsonArr>(val.v)) {
        out.push_back('[');
        const auto &arr = std::get<JsonArr>(val.v);
        for (size_t i = 0; i < arr.size(); ++i) {
            if (i > 0) out.push_back(',');
            serialize_jcs_value(out, arr[i]);
        }
        out.push_back(']');
    } else if (std::holds_alternative<JsonObj>(val.v)) {
        out.push_back('{');
        const auto &obj = std::get<JsonObj>(val.v);
        bool first = true;
        for (const auto &[k, v] : obj) {
            if (!first) out.push_back(',');
            first = false;
            serialize_jcs_string(out, k);
            out.push_back(':');
            serialize_jcs_value(out, v);
        }
        out.push_back('}');
    }
}

std::vector<uint8_t> decode_base64url(std::string_view in) {
    static const int8_t T[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,63,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    if (in.size() % 4 == 1) throw std::runtime_error("ERR_SIGNATURE: invalid base64url length");
    std::vector<uint8_t> out;
    uint32_t buf = 0;
    int bits = 0;
    for (unsigned char c : in) {
        int8_t val = T[c];
        if (val < 0) throw std::runtime_error("ERR_SIGNATURE: invalid base64url char");
        buf = (buf << 6) | static_cast<uint32_t>(val);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF));
        }
    }
    if (bits > 0 && ((buf & ((1u << bits) - 1)) != 0))
        throw std::runtime_error("ERR_SIGNATURE: non-canonical base64url padding bits");
    return out;
}

std::vector<uint8_t> decode_hex(std::string_view hex) {
    if (hex.size() % 2 != 0) throw std::runtime_error("invalid hex length");
    std::vector<uint8_t> out(hex.size() / 2);
    for (size_t i = 0; i < out.size(); ++i) {
        auto nyb = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
            if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
            if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
            throw std::runtime_error("invalid hex character");
        };
        out[i] = static_cast<uint8_t>((nyb(hex[2 * i]) << 4) | nyb(hex[2 * i + 1]));
    }
    return out;
}

void encode_cbor_head(std::vector<uint8_t> &out, uint8_t major, uint64_t arg) {
    uint8_t mt = static_cast<uint8_t>(major << 5);
    if (arg < 24) {
        out.push_back(static_cast<uint8_t>(mt | arg));
    } else if (arg <= 0xFF) {
        out.push_back(static_cast<uint8_t>(mt | 24));
        out.push_back(static_cast<uint8_t>(arg));
    } else if (arg <= 0xFFFF) {
        out.push_back(static_cast<uint8_t>(mt | 25));
        out.push_back(static_cast<uint8_t>((arg >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(arg & 0xFF));
    } else if (arg <= 0xFFFFFFFFULL) {
        out.push_back(static_cast<uint8_t>(mt | 26));
        for (int i = 3; i >= 0; --i)
            out.push_back(static_cast<uint8_t>((arg >> (8 * i)) & 0xFF));
    } else {
        out.push_back(static_cast<uint8_t>(mt | 27));
        for (int i = 7; i >= 0; --i)
            out.push_back(static_cast<uint8_t>((arg >> (8 * i)) & 0xFF));
    }
}

void serialize_dcbor_value(std::vector<uint8_t> &out, const JsonVal &val) {
    if (std::holds_alternative<std::monostate>(val.v)) {
        out.push_back(0xF6);
    } else if (std::holds_alternative<bool>(val.v)) {
        out.push_back(std::get<bool>(val.v) ? 0xF5 : 0xF4);
    } else if (std::holds_alternative<int64_t>(val.v)) {
        int64_t n = std::get<int64_t>(val.v);
        if (n >= 0) {
            encode_cbor_head(out, 0, static_cast<uint64_t>(n));
        } else {
            encode_cbor_head(out, 1, static_cast<uint64_t>(-1 - n));
        }
    } else if (std::holds_alternative<std::string>(val.v)) {
        const auto &s = std::get<std::string>(val.v);
        encode_cbor_head(out, 3, s.size());
        out.insert(out.end(), s.begin(), s.end());
    } else if (std::holds_alternative<JsonArr>(val.v)) {
        const auto &arr = std::get<JsonArr>(val.v);
        encode_cbor_head(out, 4, arr.size());
        for (const auto &item : arr) {
            serialize_dcbor_value(out, item);
        }
    } else if (std::holds_alternative<JsonObj>(val.v)) {
        const auto &obj = std::get<JsonObj>(val.v);
        struct PairBytes {
            std::vector<uint8_t> k;
            std::vector<uint8_t> v;
        };
        std::vector<PairBytes> pairs;
        pairs.reserve(obj.size());
        for (const auto &[k, v] : obj) {
            std::vector<uint8_t> ek, ev;
            encode_cbor_head(ek, 3, k.size());
            ek.insert(ek.end(), k.begin(), k.end());
            serialize_dcbor_value(ev, v);
            pairs.push_back({std::move(ek), std::move(ev)});
        }
        std::sort(pairs.begin(), pairs.end(), [](const PairBytes &a, const PairBytes &b) {
            return a.k < b.k;
        });
        encode_cbor_head(out, 5, pairs.size());
        for (const auto &p : pairs) {
            out.insert(out.end(), p.k.begin(), p.k.end());
            out.insert(out.end(), p.v.begin(), p.v.end());
        }
    }
}

struct DcborDecoder {
    const uint8_t* data{};
    size_t size{0};
    size_t pos{0};
    bool allow_unicode_keys{false};

    std::pair<uint8_t, uint64_t> read_head() {
        if (pos >= size)
            throw std::runtime_error("ERR_SCHEMA: truncated CBOR stream");
        uint8_t ib = data[pos++];
        uint8_t major = ib >> 5;
        uint8_t ai = ib & 0x1F;
        if (ai < 24) {
            return {major, ai};
        }
        if (ai == 24) {
            if (pos + 1 > size) throw std::runtime_error("ERR_SCHEMA: truncated CBOR uint8");
            uint64_t val = data[pos++];
            if (val < 24) throw std::runtime_error("ERR_SCHEMA: non-minimal CBOR uint8 encoding");
            return {major, val};
        }
        if (ai == 25) {
            if (pos + 2 > size) throw std::runtime_error("ERR_SCHEMA: truncated CBOR uint16");
            uint64_t val = (static_cast<uint64_t>(data[pos]) << 8) | data[pos + 1];
            pos += 2;
            if (val <= 0xFF) throw std::runtime_error("ERR_SCHEMA: non-minimal CBOR uint16 encoding");
            return {major, val};
        }
        if (ai == 26) {
            if (pos + 4 > size) throw std::runtime_error("ERR_SCHEMA: truncated CBOR uint32");
            uint64_t val = 0;
            for (int i = 0; i < 4; ++i) val = (val << 8) | data[pos + i];
            pos += 4;
            if (val <= 0xFFFF) throw std::runtime_error("ERR_SCHEMA: non-minimal CBOR uint32 encoding");
            return {major, val};
        }
        if (ai == 27) {
            if (pos + 8 > size) throw std::runtime_error("ERR_SCHEMA: truncated CBOR uint64");
            uint64_t val = 0;
            for (int i = 0; i < 8; ++i) val = (val << 8) | data[pos + i];
            pos += 8;
            if (val <= 0xFFFFFFFFULL) throw std::runtime_error("ERR_SCHEMA: non-minimal CBOR uint64 encoding");
            return {major, val};
        }
        if (ai == 31)
            throw std::runtime_error("ERR_SCHEMA: indefinite-length CBOR forbidden in dCBOR");
        throw std::runtime_error("ERR_SCHEMA: invalid CBOR additional info");
    }

    JsonVal decode_item(int depth) {
        if (depth > 40)
            throw std::runtime_error("ERR_SCHEMA: CBOR nesting depth exceeded");
        auto [major, arg] = read_head();
        constexpr uint64_t MAX_SAFE = (1ULL << 53) - 1;
        if (major == 0) {
            if (arg > MAX_SAFE)
                throw std::runtime_error("ERR_SCHEMA: CBOR unsigned int exceeds IEEE-754 safe integer range");
            return JsonVal{static_cast<int64_t>(arg)};
        }
        if (major == 1) {
            if (arg >= (1ULL << 53) - 1)
                throw std::runtime_error("ERR_SCHEMA: CBOR negative int exceeds IEEE-754 safe integer range");
            int64_t val = -1 - static_cast<int64_t>(arg);
            return JsonVal{val};
        }
        if (major == 2) {
            throw std::runtime_error("ERR_SCHEMA: raw CBOR byte strings forbidden in JSON-bijective wire profile");
        }
        if (major == 3) {
            if (pos + arg > size)
                throw std::runtime_error("ERR_SCHEMA: truncated CBOR text string");
            std::string s(reinterpret_cast<const char*>(data + pos), static_cast<size_t>(arg));
            pos += static_cast<size_t>(arg);
            (void)utf8_to_utf16_units(s);
            return JsonVal{std::move(s)};
        }
        if (major == 4) {
            if (arg > 65536)
                throw std::runtime_error("ERR_SCHEMA: CBOR array length exceeded");
            JsonArr arr;
            arr.reserve(static_cast<size_t>(arg));
            for (uint64_t i = 0; i < arg; ++i) {
                arr.push_back(decode_item(depth + 1));
            }
            return JsonVal{std::move(arr)};
        }
        if (major == 5) {
            if (arg > 65536)
                throw std::runtime_error("ERR_SCHEMA: CBOR map length exceeded");
            JsonObj obj;
            std::vector<uint8_t> prev_key_bytes;
            bool has_prev = false;
            for (uint64_t i = 0; i < arg; ++i) {
                size_t k_start = pos;
                JsonVal k_val = decode_item(depth + 1);
                size_t k_end = pos;
                if (!std::holds_alternative<std::string>(k_val.v))
                    throw std::runtime_error("ERR_SCHEMA: CBOR map key must be text string");
                const std::string &k_str = std::get<std::string>(k_val.v);
                if (!allow_unicode_keys) {
                    if (k_str.empty()) throw std::runtime_error("ERR_SCHEMA: empty CBOR map key");
                    for (unsigned char ch : k_str) {
                        if (ch < 0x21 || ch > 0x7E)
                            throw std::runtime_error("ERR_SCHEMA: non-ASCII CBOR member name");
                    }
                }
                std::vector<uint8_t> cur_key_bytes(data + k_start, data + k_end);
                if (has_prev && cur_key_bytes <= prev_key_bytes)
                    throw std::runtime_error("ERR_SCHEMA: non-canonical or duplicate CBOR map key order");
                prev_key_bytes = std::move(cur_key_bytes);
                has_prev = true;
                JsonVal v_val = decode_item(depth + 1);
                obj.emplace(k_str, std::move(v_val));
            }
            return JsonVal{std::move(obj)};
        }
        if (major == 7) {
            if (arg == 20) return JsonVal{false};
            if (arg == 21) return JsonVal{true};
            if (arg == 22) return JsonVal{std::monostate{}};
            throw std::runtime_error("ERR_SCHEMA: unsupported CBOR simple value or float");
        }
        throw std::runtime_error("ERR_SCHEMA: unsupported CBOR major type");
    }
};

void check_no_unsupported_critical(const JsonObj &obj) {
    auto crit_it = obj.find("critical");
    if (crit_it == obj.end()) return;
    if (!std::holds_alternative<JsonArr>(crit_it->second.v))
        throw std::runtime_error("ERR_SCHEMA: critical must be array");
    const auto &arr = std::get<JsonArr>(crit_it->second.v);
    if (arr.empty())
        throw std::runtime_error("ERR_SCHEMA: critical array cannot be empty");
    throw std::runtime_error("ERR_VERSION: unsupported critical extension in envelope");
}

// Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493 in little-endian bytes
static constexpr uint8_t ED25519_L_LE[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

bool is_ed25519_scalar_canonical(const uint8_t sig[64]) {
    for (int i = 31; i >= 0; --i) {
        if (sig[32 + i] < ED25519_L_LE[i]) return true;
        if (sig[32 + i] > ED25519_L_LE[i]) return false;
    }
    return false; // S == L is non-canonical
}

bool is_weak_pubkey_hex(std::string_view hex) {
    return hex == "0000000000000000000000000000000000000000000000000000000000000000" ||
           hex == "0100000000000000000000000000000000000000000000000000000000000000" ||
           hex == "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f" ||
           hex == "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f" ||
           hex == "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f";
}

bool verify_decoded_cbor_obj(JsonVal &root, std::string_view pubkey_hex) {
    if (!std::holds_alternative<JsonObj>(root.v))
        throw std::runtime_error("ERR_SCHEMA: envelope must be object");
    auto &obj = std::get<JsonObj>(root.v);
    check_no_unsupported_critical(obj);
    auto auth_it = obj.find("auth");
    auto proof_it = obj.find("proof");
    if (auth_it == obj.end() || proof_it == obj.end() ||
        !std::holds_alternative<JsonObj>(auth_it->second.v) ||
        !std::holds_alternative<JsonObj>(proof_it->second.v))
        throw std::runtime_error("ERR_SIGNATURE: missing auth or proof");

    const auto &proof_obj = std::get<JsonObj>(proof_it->second.v);
    if ((proof_obj.size() != 2 && proof_obj.size() != 3) || !proof_obj.count("alg") || !proof_obj.count("sig"))
        throw std::runtime_error("ERR_SIGNATURE: invalid proof shape");
    if (!std::holds_alternative<std::string>(proof_obj.at("alg").v) ||
        std::get<std::string>(proof_obj.at("alg").v) != "Ed25519")
        throw std::runtime_error("ERR_SIGNATURE: unsupported algorithm");
    if (!std::holds_alternative<std::string>(proof_obj.at("sig").v))
        throw std::runtime_error("ERR_SIGNATURE: invalid sig field");

    std::vector<uint8_t> sig = decode_base64url(std::get<std::string>(proof_obj.at("sig").v));
    if (sig.size() != 64 || !is_ed25519_scalar_canonical(sig.data()))
        throw std::runtime_error("ERR_SIGNATURE: Ed25519 signature must be 64 bytes with canonical S < L");
    if (is_weak_pubkey_hex(pubkey_hex))
        throw std::runtime_error("ERR_KEY_UNBOUND: weak or small-order public key rejected");

    std::vector<uint8_t> pub = decode_hex(pubkey_hex);
    if (pub.size() != 32)
        throw std::runtime_error("ERR_KEY_UNBOUND: Ed25519 public key must be 32 bytes");

    obj.erase(proof_it);
    static constexpr char prefix[] = "WUTONG-CBOR-SIG-V0.1";
    std::vector<uint8_t> signing_input(prefix, prefix + sizeof(prefix));
    serialize_dcbor_value(signing_input, root);

    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub.data(), pub.size());
    if (!pkey) throw std::runtime_error("EVP_PKEY_new_raw_public_key failed");
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }
    int ok = 0;
    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        ok = EVP_DigestVerify(ctx, sig.data(), sig.size(), signing_input.data(), signing_input.size());
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok == 1;
}

} // namespace

std::string jcs_canonicalize(std::string_view json_utf8, bool allow_unicode_keys) {
    if (json_utf8.size() > 1048576)
        throw std::runtime_error("ERR_SCHEMA: size exceeded");
    (void)utf8_to_utf16_units(json_utf8);
    Parser p{json_utf8, 0, allow_unicode_keys};
    JsonVal root = p.parse_value(0);
    p.skip_ws();
    if (p.pos != json_utf8.size())
        throw std::runtime_error("ERR_SCHEMA: trailing data after JSON root");
    std::string out;
    serialize_jcs_value(out, root);
    return out;
}

bool verify_signed_envelope(std::string_view envelope_json, std::string_view pubkey_hex) {
    (void)utf8_to_utf16_units(envelope_json);
    Parser p{envelope_json, 0, false};
    JsonVal root = p.parse_value(0);
    p.skip_ws();
    if (p.pos != envelope_json.size() || !std::holds_alternative<JsonObj>(root.v))
        throw std::runtime_error("ERR_SCHEMA: envelope must be JSON object");

    auto &obj = std::get<JsonObj>(root.v);
    check_no_unsupported_critical(obj);
    auto auth_it = obj.find("auth");
    auto proof_it = obj.find("proof");
    if (auth_it == obj.end() || proof_it == obj.end() ||
        !std::holds_alternative<JsonObj>(auth_it->second.v) ||
        !std::holds_alternative<JsonObj>(proof_it->second.v))
        throw std::runtime_error("ERR_SIGNATURE: missing auth or proof");

    const auto &proof_obj = std::get<JsonObj>(proof_it->second.v);
    if ((proof_obj.size() != 2 && proof_obj.size() != 3) || !proof_obj.count("alg") || !proof_obj.count("sig"))
        throw std::runtime_error("ERR_SIGNATURE: invalid proof shape");
    if (!std::holds_alternative<std::string>(proof_obj.at("alg").v) ||
        std::get<std::string>(proof_obj.at("alg").v) != "Ed25519")
        throw std::runtime_error("ERR_SIGNATURE: unsupported algorithm");
    if (!std::holds_alternative<std::string>(proof_obj.at("sig").v))
        throw std::runtime_error("ERR_SIGNATURE: invalid sig field");

    std::vector<uint8_t> sig = decode_base64url(std::get<std::string>(proof_obj.at("sig").v));
    if (sig.size() != 64 || !is_ed25519_scalar_canonical(sig.data()))
        throw std::runtime_error("ERR_SIGNATURE: Ed25519 signature must be 64 bytes with canonical S < L");
    if (is_weak_pubkey_hex(pubkey_hex))
        throw std::runtime_error("ERR_KEY_UNBOUND: weak or small-order public key rejected");

    std::vector<uint8_t> pub = decode_hex(pubkey_hex);
    if (pub.size() != 32)
        throw std::runtime_error("ERR_KEY_UNBOUND: Ed25519 public key must be 32 bytes");

    obj.erase(proof_it);
    std::string canonical;
    serialize_jcs_value(canonical, root);

    static constexpr char prefix[] = "WUTONG-SIG-V0.1";
    std::string signing_input(prefix, sizeof(prefix)); // includes trailing NUL byte!
    signing_input += canonical;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub.data(), pub.size());
    if (!pkey) throw std::runtime_error("EVP_PKEY_new_raw_public_key failed");
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }
    int ok = 0;
    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        ok = EVP_DigestVerify(
            ctx,
            sig.data(),
            sig.size(),
            reinterpret_cast<const unsigned char*>(signing_input.data()),
            signing_input.size()
        );
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok == 1;
}

std::vector<uint8_t> json_to_dcbor(std::string_view json_utf8, bool allow_unicode_keys) {
    if (json_utf8.size() > 1048576)
        throw std::runtime_error("ERR_SCHEMA: size exceeded");
    (void)utf8_to_utf16_units(json_utf8);
    Parser p{json_utf8, 0, allow_unicode_keys};
    JsonVal root = p.parse_value(0);
    p.skip_ws();
    if (p.pos != json_utf8.size())
        throw std::runtime_error("ERR_SCHEMA: trailing data after JSON root");
    std::vector<uint8_t> out;
    serialize_dcbor_value(out, root);
    return out;
}

std::string dcbor_to_hex(std::string_view json_utf8, bool allow_unicode_keys) {
    auto bytes = json_to_dcbor(json_utf8, allow_unicode_keys);
    std::ostringstream s;
    s << std::hex << std::setfill('0');
    for (uint8_t b : bytes) s << std::setw(2) << int(b);
    return s.str();
}

std::string dcbor_to_jcs(const std::vector<uint8_t> &cbor_bytes, bool allow_unicode_keys) {
    if (cbor_bytes.empty() || cbor_bytes.size() > 1048576)
        throw std::runtime_error("ERR_SCHEMA: invalid CBOR byte length");
    DcborDecoder dec{cbor_bytes.data(), cbor_bytes.size(), 0, allow_unicode_keys};
    JsonVal root = dec.decode_item(0);
    if (dec.pos != cbor_bytes.size())
        throw std::runtime_error("ERR_SCHEMA: trailing bytes after CBOR root item");
    std::string out;
    serialize_jcs_value(out, root);
    return out;
}

std::string dcbor_hex_to_jcs(std::string_view cbor_hex, bool allow_unicode_keys) {
    return dcbor_to_jcs(decode_hex(cbor_hex), allow_unicode_keys);
}

bool verify_signed_cbor_envelope(std::string_view envelope_json, std::string_view pubkey_hex) {
    (void)utf8_to_utf16_units(envelope_json);
    Parser p{envelope_json, 0, false};
    JsonVal root = p.parse_value(0);
    p.skip_ws();
    if (p.pos != envelope_json.size())
        throw std::runtime_error("ERR_SCHEMA: trailing data after JSON root");
    return verify_decoded_cbor_obj(root, pubkey_hex);
}

bool verify_raw_cbor_hex_envelope(std::string_view cbor_hex, std::string_view pubkey_hex) {
    std::vector<uint8_t> raw = decode_hex(cbor_hex);
    if (raw.empty() || raw.size() > 1048576)
        throw std::runtime_error("ERR_SCHEMA: invalid CBOR byte length");
    DcborDecoder dec{raw.data(), raw.size(), 0, false};
    JsonVal root = dec.decode_item(0);
    if (dec.pos != raw.size())
        throw std::runtime_error("ERR_SCHEMA: trailing bytes after CBOR root item");
    return verify_decoded_cbor_obj(root, pubkey_hex);
}

std::string apply_source_patch(std::string_view base_bytes, size_t start_byte, size_t end_byte,
                               std::string_view expected_slice_sha256, std::string_view replacement) {
    if (start_byte > end_byte || end_byte > base_bytes.size())
        throw std::runtime_error("ERR_CONFLICT: patch range out of bounds");
    std::string_view slice = base_bytes.substr(start_byte, end_byte - start_byte);
    if (sha256_hex(slice) != expected_slice_sha256)
        throw std::runtime_error("ERR_CONFLICT: patch slice sha256 mismatch");
    std::string out;
    out.reserve(base_bytes.size() - slice.size() + replacement.size());
    out.append(base_bytes.substr(0, start_byte));
    out.append(replacement);
    out.append(base_bytes.substr(end_byte));
    return out;
}

} // namespace wutong
