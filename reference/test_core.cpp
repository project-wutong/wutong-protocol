// SPDX-License-Identifier: AGPL-3.0-only
#include "wutong/core.hpp"
#include <openssl/evp.h>
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <stdexcept>
#include <string>

using namespace wutong;
namespace fs=std::filesystem;
static void write_bytes(const fs::path &p,const std::string& v){std::ofstream o(p,std::ios::binary|std::ios::trunc);o.write(v.data(), static_cast<std::streamsize>(v.size()));}
template<class F> static void expect_reject(F fn){bool rejected=false;try{fn();}catch(const std::exception&){rejected=true;}assert(rejected);}
static void ed25519_smoke_test() {
  EVP_PKEY_CTX* ctx=EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519,nullptr);assert(ctx);
  EVP_PKEY* key=nullptr;assert(EVP_PKEY_keygen_init(ctx)==1);assert(EVP_PKEY_keygen(ctx,&key)==1);EVP_PKEY_CTX_free(ctx);
  const std::string signed_data("WUTONG\0CORE-v0.1:example", sizeof("WUTONG\0CORE-v0.1:example")-1);
  const std::string altered="tampered";
  assert(signed_data.find('\0') != std::string::npos);
  EVP_MD_CTX *sign=EVP_MD_CTX_new();assert(EVP_DigestSignInit(sign,nullptr,nullptr,nullptr,key)==1);
  unsigned char signature[128];size_t siglen=sizeof(signature);
  assert(EVP_DigestSign(sign,signature,&siglen,reinterpret_cast<const unsigned char*>(signed_data.data()),signed_data.size())==1);
  EVP_MD_CTX_free(sign);
  auto verify=[&](const std::string& payload){EVP_MD_CTX* v=EVP_MD_CTX_new();assert(EVP_DigestVerifyInit(v,nullptr,nullptr,nullptr,key)==1);int ok=EVP_DigestVerify(v,signature,siglen,reinterpret_cast<const unsigned char*>(payload.data()),payload.size());EVP_MD_CTX_free(v);return ok==1;};
  assert(verify(signed_data));assert(!verify(altered));EVP_PKEY_free(key);
}
int main(){
  auto temp=fs::temp_directory_path()/("wutong-core-poc-"+uuid_v7_urn().substr(9));fs::create_directories(temp);
  auto file=temp/"notes.md";
  const std::string original="# 梧桐计划\r\n初始 **Markdown** 文本。\r\n";
  write_bytes(file,original);
  std::string oid, owner, agent, oldhash;
  {
    Store db(temp/"local.sqlite");
    owner=db.create_principal("human","Writer User");agent=db.create_principal("agent","Review Agent");
    auto d=db.import_file(file,owner,"text/markdown");oid=d.id;oldhash=d.head_digest;
    assert(std::regex_match(oid,std::regex(R"(^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$)")));
    assert(d.path==fs::absolute(file).string());assert(read_bytes(file)==original);
    assert(d.head_digest==sha256_hex(original));assert(db.revision_count(oid)==1);
    assert(db.import_file(file,owner,"text/markdown").id==oid);
    expect_reject([&]{db.propose_replace(agent,oid,oldhash,"not authorized");});
    db.grant_local(owner,agent,oid,"document.propose");
    const auto pid=db.propose_replace(agent,oid,oldhash,"# 新标题\r\nAgent 提议。\r\n");
    assert(db.has_pending_proposal(pid));assert(read_bytes(file)==original);
    expect_reject([&]{db.approve_apply(agent,pid);});
    const std::string external="# 外部修改\r\n仍保留 CRLF。\r\n";write_bytes(file,external);
    expect_reject([&]{db.approve_apply(owner,pid);});
    assert(db.refresh_from_disk(oid,owner)==sha256_hex(external));
    assert(db.revision_count(oid)==2);
    expect_reject([&]{db.propose_replace(agent,oid,oldhash,"stale");});
    const auto newpid=db.propose_replace(agent,oid,sha256_hex(external),"# 审核完成\r\nUTF-8 文档。\r\n");
    db.approve_apply(owner,newpid);
    assert(!db.has_pending_proposal(newpid));
    assert(read_bytes(file)=="# 审核完成\r\nUTF-8 文档。\r\n");
    assert(db.revision_count(oid)==3);
    expect_reject([&]{db.approve_apply(owner,newpid);});
    auto rid=db.create_relation(owner,oid,"https://example.org/reference","references");assert(rid.starts_with("urn:uuid:"));
    expect_reject([&]{db.create_relation(agent,oid,"https://example.org/other","references");});
    assert(db.event_count()>=7);
  }
  {Store db(temp/"local.sqlite");auto d=db.document(oid);assert(d.head_digest==sha256_hex(read_bytes(file)));assert(d.owner==owner);assert(db.revision_count(oid)==3);}
  assert(sha256_hex("")=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  ed25519_smoke_test();
  std::cout<<"PASS: 18 offline Core verification assertions/groups (incl. UUIDv7, UTF-8, CRLF, identity, stable IDs, SHA-256, unauthorized agent, proposal, stale rejection, external refresh, human review, revision chain, relation, persistence, Ed25519 sign/verify)\n";
  fs::remove_all(temp);
}
