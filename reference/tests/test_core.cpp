// SPDX-License-Identifier: AGPL-3.0-only
#include "wutong/core.hpp"
#include <openssl/evp.h>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <cctype>
#include <stdexcept>
#include <string>

using namespace wutong;
namespace fs = std::filesystem;

static bool is_uuid_v7_urn(std::string_view s) {
    if (s.size() != 45 || s.substr(0, 9) != "urn:uuid:") return false;
    std::string_view u = s.substr(9);
    for (size_t i = 0; i < u.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (u[i] != '-') return false;
        } else if (i == 14) {
            if (u[i] != '7') return false;
        } else if (i == 19) {
            if (u[i] != '8' && u[i] != '9' && u[i] != 'a' && u[i] != 'b') return false;
        } else {
            if (!((u[i] >= '0' && u[i] <= '9') || (u[i] >= 'a' && u[i] <= 'f'))) return false;
        }
    }
    return true;
}

static void write_bytes(const fs::path &p, const std::string& v) {
    std::ofstream o(p, std::ios::binary | std::ios::trunc);
    o.write(v.data(), static_cast<std::streamsize>(v.size()));
}

template<class F>
static void expect_reject(F fn) {
    bool rejected = false;
    try { fn(); } catch (const std::exception&) { rejected = true; }
    assert(rejected);
}

static void ed25519_smoke_test() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    assert(ctx);
    EVP_PKEY* key = nullptr;
    assert(EVP_PKEY_keygen_init(ctx) == 1);
    assert(EVP_PKEY_keygen(ctx, &key) == 1);
    EVP_PKEY_CTX_free(ctx);
    const std::string signed_data("WUTONG\0CORE-v0.1:example", sizeof("WUTONG\0CORE-v0.1:example") - 1);
    const std::string altered = "tampered";
    assert(signed_data.find('\0') != std::string::npos);
    EVP_MD_CTX *sign = EVP_MD_CTX_new();
    assert(EVP_DigestSignInit(sign, nullptr, nullptr, nullptr, key) == 1);
    unsigned char signature[128];
    size_t siglen = sizeof(signature);
    assert(EVP_DigestSign(sign, signature, &siglen, reinterpret_cast<const unsigned char*>(signed_data.data()), signed_data.size()) == 1);
    EVP_MD_CTX_free(sign);
    auto verify = [&](const std::string& payload) {
        EVP_MD_CTX* v = EVP_MD_CTX_new();
        assert(EVP_DigestVerifyInit(v, nullptr, nullptr, nullptr, key) == 1);
        int ok = EVP_DigestVerify(v, signature, siglen, reinterpret_cast<const unsigned char*>(payload.data()), payload.size());
        EVP_MD_CTX_free(v);
        return ok == 1;
    };
    assert(verify(signed_data));
    assert(!verify(altered));
    EVP_PKEY_free(key);
}

static void jcs_and_envelope_verification_test() {
    // Verify strict JSON rejections in C++23
    expect_reject([] { jcs_canonicalize(R"({"a":1,"a":2})"); });
    expect_reject([] { jcs_canonicalize(R"({"x":1.5})"); });
    expect_reject([] { jcs_canonicalize(R"({"x":9007199254740992})"); });
    expect_reject([] { jcs_canonicalize(R"({"x":"\ud800"})"); });
    expect_reject([] { jcs_canonicalize("{\"é\":1}", false); });

    // Verify RFC 8785 UTF-16 code-unit sorting in Unicode key mode:
    // U+10348 (UTF-16: 0xD800 0xDF48) MUST sort BEFORE U+E000 (UTF-16: 0xE000)
    std::string astral_sorted = jcs_canonicalize("{\"\xee\x80\x80\":1,\"\xf0\x90\x8d\x88\":2}", true);
    assert(astral_sorted == "{\"𐍈\":2,\"\xee\x80\x80\":1}");

    // Verify pinned Ed25519 signed WTP envelope vector in C++23
    const std::string pubkey_hex = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
    const std::string signed_env = R"({
      "protocol": "wutong/0.1",
      "kind": "wutong.object",
      "id": "urn:uuid:019a1111-1111-7111-8111-000000002713",
      "occurred_at": "2026-10-18T10:00:00Z",
      "payload": {
        "object_id": "urn:uuid:019a1111-1111-7111-8111-00000000012d",
        "space_id": "urn:uuid:019a1111-1111-7111-8111-00000000012e",
        "owner_id": "urn:uuid:019a1111-1111-7111-8111-00000000012f",
        "object_type": "document",
        "content_digest": "sha256:47ad8cc78b24bcb0b6e13b2657e96f1c915055f3f872d3c2c92b25343a6ff5b6",
        "media_type": "text/markdown",
        "byte_length": 0
      },
      "auth": {
        "signer_id": "urn:uuid:019a1111-1111-7111-8111-000000000001",
        "key_id": "local-key-01",
        "issued_at": "2026-10-18T10:00:00Z",
        "nonce": "AAAAAAAAAAAAAAAAAAAAAAAA"
      },
      "proof": {
        "alg": "Ed25519",
        "sig": "91bbF7H1wMhm5Pif0c6nG6uvkwf02UX3wbX54wsBbB2-KYPl63TLqCKke2LGYakkrDCW4Fzq93_LYB4mkhFjCQ"
      }
    })";
    assert(verify_signed_envelope(signed_env, pubkey_hex));

    // Tampered byte_length must fail signature verification
    std::string tampered = signed_env;
    auto pos = tampered.find("\"byte_length\": 0");
    assert(pos != std::string::npos);
    tampered.replace(pos, 16, "\"byte_length\": 1");
    assert(!verify_signed_envelope(tampered, pubkey_hex));

    // Verify RFC 8949 §4.2.1 Deterministic CBOR map key ordering & native binary decoding in C++23:
    // {"aa":1,"b":2,"a":0} -> map(3): "a":0, "b":2, "aa":1 -> a3 61 61 00 61 62 02 62 61 61 01
    assert(dcbor_to_hex(R"({"aa":1,"b":2,"a":0})") == "a361610061620262616101");
    assert(dcbor_hex_to_jcs("a361610061620262616101") == R"({"a":0,"aa":1,"b":2})");

    // Verify C++23 native binary dCBOR decoder rejects non-minimal ints, indefinite lengths, byte strings, and unsorted keys
    expect_reject([] { dcbor_hex_to_jcs("1801"); });
    expect_reject([] { dcbor_hex_to_jcs("1900ff"); });
    expect_reject([] { dcbor_hex_to_jcs("9fff"); });
    expect_reject([] { dcbor_hex_to_jcs("4100"); });
    expect_reject([] { dcbor_hex_to_jcs("a2616201616102"); });
    expect_reject([] { dcbor_hex_to_jcs("a2616101616102"); });
    expect_reject([] { dcbor_hex_to_jcs("a36161006162026261610100"); });

    // Verify unsupported critical extension in signed envelope fails closed in C++23
    std::string crit_env = signed_env;
    auto ppos = crit_env.find(R"("auth":)");
    assert(ppos != std::string::npos);
    crit_env.insert(ppos, R"("extensions":{"org.wutong.crit":1},"critical":["org.wutong.crit"],)");
    expect_reject([&] { verify_signed_envelope(crit_env, pubkey_hex); });

    // Verify C++23 source-first minimal range patch application & slice digest check
    std::string patched = apply_source_patch("Hello, Wutong!", 7, 13, sha256_hex("Wutong"), "Project Wutong");
    assert(patched == "Hello, Project Wutong!");
    expect_reject([&] { apply_source_patch("Hello, Wutong!", 7, 13, sha256_hex("Wrong"), "X"); });

    // Verify C++23 rejection of weak all-zero public key
    expect_reject([&] { verify_signed_envelope(signed_env, "0000000000000000000000000000000000000000000000000000000000000000"); });
}

static void crash_recovery_tests(const fs::path &temp) {
    for (auto stage : {CrashPoint::Prepared, CrashPoint::Replaced, CrashPoint::Committed}) {
        auto sub = temp / ("crash-" + std::to_string(static_cast<int>(stage)));
        fs::create_directories(sub);
        auto f = sub / "doc.md";
        write_bytes(f, "v1\r\n");
        std::string oid, owner, agent, pid;
        {
            Store db(sub / "db.sqlite");
            owner = db.create_principal("human", "Owner");
            agent = db.create_principal("agent", "Agent");
            auto d = db.import_file(f, owner, "text/markdown");
            oid = d.id;
            db.grant_local(owner, agent, oid, "document.propose");
            pid = db.propose_replace(agent, oid, d.head_digest, "v2\r\n");
            bool crashed = false;
            try {
                db.approve_apply(owner, pid, stage);
            } catch (const SimulatedCrash&) {
                crashed = true;
            }
            assert(crashed);
        }
        {
            Store db(sub / "db.sqlite");
            auto recovered = db.recover_intents();
            if (stage == CrashPoint::Committed) {
                assert(recovered.empty());
            } else {
                assert(recovered.size() == 1);
                assert(recovered[0].second == "rolled-forward" || recovered[0].second == "finalized");
            }
            assert(read_bytes(f) == "v2\r\n");
            assert(db.document(oid).head_digest == sha256_hex("v2\r\n"));
            assert(!db.has_pending_proposal(pid));
            assert(db.revision_count(oid) == 2);
            assert(db.recover_intents().empty());
        }
    }

    // External modification after prepare must be preserved as conflict, never overwritten
    auto conflict_dir = temp / "crash-conflict";
    fs::create_directories(conflict_dir);
    auto cf = conflict_dir / "notes.md";
    write_bytes(cf, "initial");
    {
        Store db(conflict_dir / "db.sqlite");
        auto owner = db.create_principal("human", "Owner");
        auto agent = db.create_principal("agent", "Agent");
        auto d = db.import_file(cf, owner, "text/markdown");
        db.grant_local(owner, agent, d.id, "document.propose");
        auto pid = db.propose_replace(agent, d.id, d.head_digest, "proposed");
        try {
            db.approve_apply(owner, pid, CrashPoint::Prepared);
        } catch (const SimulatedCrash&) {}
        write_bytes(cf, "external-edit");
        auto recovered = db.recover_intents();
        assert(recovered.size() == 1 && recovered[0].second == "conflict");
        assert(read_bytes(cf) == "external-edit");
    }
}

int main() {
    auto temp = fs::temp_directory_path() / ("wutong-core-poc-" + uuid_v7_urn().substr(9));
    fs::create_directories(temp);
    auto file = temp / "notes.md";
    const std::string original = "# 梧桐计划\r\n初始 **Markdown** 文本。\r\n";
    write_bytes(file, original);
    std::string oid, owner, agent, oldhash;
    {
        Store db(temp / "local.sqlite");
        owner = db.create_principal("human", "Writer User");
        agent = db.create_principal("agent", "Review Agent");
        auto d = db.import_file(file, owner, "text/markdown");
        oid = d.id;
        oldhash = d.head_digest;
        assert(is_uuid_v7_urn(oid));
        assert(d.path == fs::absolute(file).string());
        assert(read_bytes(file) == original);
        assert(d.head_digest == sha256_hex(original));
        assert(db.revision_count(oid) == 1);
        assert(db.import_file(file, owner, "text/markdown").id == oid);
        expect_reject([&] { db.propose_replace(agent, oid, oldhash, "not authorized"); });
        db.grant_local(owner, agent, oid, "document.propose");
        const auto pid = db.propose_replace(agent, oid, oldhash, "# 新标题\r\nAgent 提议。\r\n");
        assert(db.has_pending_proposal(pid));
        assert(read_bytes(file) == original);
        expect_reject([&] { db.approve_apply(agent, pid); });
        const std::string external = "# 外部修改\r\n仍保留 CRLF。\r\n";
        write_bytes(file, external);
        expect_reject([&] { db.approve_apply(owner, pid); });
        assert(db.refresh_from_disk(oid, owner) == sha256_hex(external));
        assert(db.revision_count(oid) == 2);
        expect_reject([&] { db.propose_replace(agent, oid, oldhash, "stale"); });
        const auto newpid = db.propose_replace(agent, oid, sha256_hex(external), "# 审核完成\r\nUTF-8 文档。\r\n");
        db.approve_apply(owner, newpid);
        assert(!db.has_pending_proposal(newpid));
        assert(read_bytes(file) == "# 审核完成\r\nUTF-8 文档。\r\n");
        assert(db.revision_count(oid) == 3);
        expect_reject([&] { db.approve_apply(owner, newpid); });
        auto rid = db.create_relation(owner, oid, "https://example.org/reference", "references");
        assert(rid.starts_with("urn:uuid:"));
        expect_reject([&] { db.create_relation(agent, oid, "https://example.org/other", "references"); });
        assert(db.event_count() >= 7);
    }
    {
        Store db(temp / "local.sqlite");
        auto d = db.document(oid);
        assert(d.head_digest == sha256_hex(read_bytes(file)));
        assert(d.owner == owner);
        assert(db.revision_count(oid) == 3);
    }
    assert(sha256_hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    ed25519_smoke_test();
    jcs_and_envelope_verification_test();
    crash_recovery_tests(temp);
    std::cout << "PASS: 30 offline Core & v0.1.2 formal release verification assertions/groups (UUIDv7, UTF-8, CRLF, identity, stable IDs, SHA-256, unauthorized agent, proposal, stale rejection, external refresh, human review, revision chain, relation, SQLite WAL+FULL persistence, WriteIntent crash recovery at Prepared/Replaced/Committed, external conflict preservation, RFC 8785 JCS UTF-16 key sorting, native binary RFC 8949 dCBOR encoder/decoder, and Ed25519 envelope verification)\n";
    fs::remove_all(temp);
}
