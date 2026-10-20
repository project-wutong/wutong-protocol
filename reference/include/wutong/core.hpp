// SPDX-License-Identifier: AGPL-3.0-only
#pragma once
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

struct sqlite3;

namespace wutong {

enum class CrashPoint {
    None,
    Prepared,
    Replaced,
    Committed
};

struct SimulatedCrash : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct Document {
    std::string id;
    std::string path;
    std::string owner;
    std::string media_type;
    std::string head_digest;
};

class Store {
public:
    explicit Store(const std::filesystem::path &db_path);
    ~Store();
    Store(const Store&) = delete;
    Store& operator=(const Store&) = delete;

    std::string create_principal(std::string_view kind, std::string_view label);
    Document import_file(const std::filesystem::path &path, std::string_view owner, std::string_view media_type);
    Document document(std::string_view id) const;
    std::string refresh_from_disk(std::string_view object_id, std::string_view actor);
    void grant_local(std::string_view owner, std::string_view subject, std::string_view object_id, std::string_view action);
    std::string propose_replace(std::string_view agent, std::string_view object_id,
                                std::string_view expected_digest, std::string_view replacement);
    void approve_apply(std::string_view reviewer, std::string_view proposal_id,
                       CrashPoint crash_at = CrashPoint::None);
    std::vector<std::pair<std::string, std::string>> recover_intents();
    std::string create_relation(std::string_view actor, std::string_view src_id,
                                std::string_view dst_id, std::string_view predicate);
    int revision_count(std::string_view object_id) const;
    int event_count() const;
    bool has_pending_proposal(std::string_view id) const;

private:
    sqlite3* db_{};
    void exec(std::string_view sql) const;
    void add_revision(std::string_view object_id, std::string_view sha256, std::string_view actor);
    void log_event(std::string_view actor, std::string_view action, std::string_view subject, std::string_view result);
    void finalize_intent(std::string_view intent_id, std::string_view proposal_id,
                         std::string_view object_id, std::string_view new_digest,
                         std::string_view reviewer);
    bool principal_exists(std::string_view id) const;
    bool can(std::string_view who, std::string_view object, std::string_view action) const;
};

std::string uuid_v7_urn();
std::string sha256_hex(std::string_view data);
std::string read_bytes(const std::filesystem::path &path);

// v0.1.2 Wire & Security C++23 APIs:
// 1. Strict JSON + RFC 8785 JCS canonicalizer & Ed25519 JSON envelope verifier
std::string jcs_canonicalize(std::string_view json_utf8, bool allow_unicode_keys = false);
bool verify_signed_envelope(std::string_view envelope_json, std::string_view pubkey_hex);

// 2. RFC 8949 §4.2.1 Deterministic CBOR (dCBOR) encoder, native binary decoder & Ed25519 CBOR envelope verifiers
std::vector<uint8_t> json_to_dcbor(std::string_view json_utf8, bool allow_unicode_keys = false);
std::string dcbor_to_hex(std::string_view json_utf8, bool allow_unicode_keys = false);
std::string dcbor_to_jcs(const std::vector<uint8_t> &cbor_bytes, bool allow_unicode_keys = false);
std::string dcbor_hex_to_jcs(std::string_view cbor_hex, bool allow_unicode_keys = false);
bool verify_signed_cbor_envelope(std::string_view envelope_json, std::string_view pubkey_hex);
bool verify_raw_cbor_hex_envelope(std::string_view cbor_hex, std::string_view pubkey_hex);
std::string apply_source_patch(std::string_view base_bytes, size_t start_byte, size_t end_byte, std::string_view expected_slice_sha256, std::string_view replacement);

} // namespace wutong
