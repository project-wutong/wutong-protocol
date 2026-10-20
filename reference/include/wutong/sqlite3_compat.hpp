// SPDX-License-Identifier: AGPL-3.0-only
#pragma once
// Minimal SQLite3 C ABI declarations for environments where libsqlite3.so.0 is present
// at runtime/link time but <sqlite3.h> headers are not installed.
#if __has_include(<sqlite3.h>)
#include <sqlite3.h>
#else
extern "C" {
struct sqlite3;
struct sqlite3_stmt;

constexpr int SQLITE_OK = 0;
constexpr int SQLITE_ROW = 100;
constexpr int SQLITE_DONE = 101;
using sqlite3_destructor_type = void (*)(void*);
#define SQLITE_TRANSIENT ((sqlite3_destructor_type)-1)

int sqlite3_open(const char *filename, sqlite3 **ppDb);
int sqlite3_close(sqlite3 *db);
int sqlite3_exec(sqlite3 *db, const char *sql, int (*callback)(void*,int,char**,char**), void *arg, char **errmsg);
void sqlite3_free(void *ptr);
const char *sqlite3_errmsg(sqlite3 *db);
int sqlite3_prepare_v2(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **ppStmt, const char **pzTail);
int sqlite3_finalize(sqlite3_stmt *pStmt);
int sqlite3_bind_text(sqlite3_stmt *pStmt, int idx, const char *val, int nBytes, sqlite3_destructor_type dtor);
int sqlite3_bind_blob(sqlite3_stmt *pStmt, int idx, const void *val, int nBytes, sqlite3_destructor_type dtor);
int sqlite3_step(sqlite3_stmt *pStmt);
const unsigned char *sqlite3_column_text(sqlite3_stmt *pStmt, int iCol);
const void *sqlite3_column_blob(sqlite3_stmt *pStmt, int iCol);
int sqlite3_column_bytes(sqlite3_stmt *pStmt, int iCol);
int sqlite3_column_int(sqlite3_stmt *pStmt, int iCol);
}
#endif
