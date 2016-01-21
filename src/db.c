#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include <sqlite3.h>

#include <tzplatform_config.h>
#include <package-manager.h>
#include <package-manager-debug.h>

#include "pkgmgr-server.h"

static const char *_get_db_path()
{
	return tzplatform_mkpath(TZ_SYS_ETC, "package-manager/blacklist.db");
}

static sqlite3 *_open_db(void)
{
	int ret;
	const char *path;
	sqlite3 *db;

	path = _get_db_path();
	if (path == NULL)
		return NULL;

	ret = sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL);
	if (ret != SQLITE_OK)
		return NULL;

	return db;
}

static int __add_blacklist_info(sqlite3 *db, uid_t uid, const char *pkgid)
{
	static const char query[] =
		"INSERT INTO blacklist (uid, idx) VALUES(?, "
		" (SELECT idx FROM blacklist_index WHERE pkgid=?))";
	int ret;
	sqlite3_stmt *stmt;

	ret = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		ERR("prepare error: %s", sqlite3_errmsg(db));
		return -1;
	}

	sqlite3_bind_int(stmt, 1, uid);
	sqlite3_bind_text(stmt, 2, pkgid, -1, SQLITE_STATIC);

	ret = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if (ret != SQLITE_DONE) {
		ERR("step error: %s", sqlite3_errmsg(db));
		return -1;
	}

	return 0;
}

static int __add_blacklist_index(sqlite3 *db, const char *pkgid)
{
	static const char query[] =
		"INSERT OR REPLACE INTO blacklist_index (pkgid, idx, ref) "
		"VALUES(?, (SELECT idx FROM blacklist_index WHERE pkgid=?),"
		" COALESCE("
		"  (SELECT ref FROM blacklist_index WHERE pkgid=?) + 1, 1))";
	int ret;
	sqlite3_stmt *stmt;

	ret = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		ERR("prepare error: %s", sqlite3_errmsg(db));
		sqlite3_close_v2(db);
		return -1;
	}

	sqlite3_bind_text(stmt, 1, pkgid, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 2, pkgid, -1, SQLITE_STATIC);
	sqlite3_bind_text(stmt, 3, pkgid, -1, SQLITE_STATIC);

	ret = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if (ret != SQLITE_DONE) {
		ERR("step error: %s", sqlite3_errmsg(db));
		return -1;
	}

	return 0;
}

int __add_blacklist(uid_t uid, const char *pkgid)
{
	int ret;
	sqlite3 *db;

	db = _open_db();
	if (db == NULL)
		return PKGMGR_R_ERROR;

	ret = sqlite3_exec(db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		sqlite3_close_v2(db);
		ERR("transaction failed");
		return PKGMGR_R_ERROR;
	}

	if (__add_blacklist_index(db, pkgid)) {
		sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close_v2(db);
		return PKGMGR_R_ERROR;
	}
	if (__add_blacklist_info(db, uid, pkgid)) {
		sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close_v2(db);
		return PKGMGR_R_ERROR;
	}

	ret = sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		ERR("commit error: %s", sqlite3_errmsg(db));
		sqlite3_close_v2(db);
		return PKGMGR_R_ERROR;
	}

	sqlite3_close_v2(db);

	return 0;
}

static int __remove_blacklist_info(sqlite3 *db, uid_t uid, const char *pkgid)
{
	static const char query[] =
		"DELETE FROM blacklist "
		"WHERE idx=(SELECT idx FROM blacklist_index WHERE pkgid=?) "
		"AND uid=?";
	int ret;
	sqlite3_stmt *stmt;

	ret = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		ERR("prepare error: %s", sqlite3_errmsg(db));
		return -1;
	}

	sqlite3_bind_text(stmt, 1, pkgid, -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 2, uid);

	ret = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if (ret != SQLITE_DONE) {
		ERR("step error: %s", sqlite3_errmsg(db));
		return -1;
	}

	return 0;
}

int __remove_blacklist(uid_t uid, const char *pkgid)
{
	int ret;
	sqlite3 *db;

	db = _open_db();
	if (db == NULL)
		return PKGMGR_R_ERROR;

	ret = sqlite3_exec(db, "BEGIN EXCLUSIVE", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		sqlite3_close_v2(db);
		ERR("transaction failed");
		return PKGMGR_R_ERROR;
	}

	if (__remove_blacklist_info(db, uid, pkgid)) {
		sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
		sqlite3_close_v2(db);
		return PKGMGR_R_ERROR;
	}

	ret = sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
	if (ret != SQLITE_OK) {
		ERR("commit error: %s", sqlite3_errmsg(db));
		sqlite3_close_v2(db);
		return PKGMGR_R_ERROR;
	}

	sqlite3_close_v2(db);

	return PKGMGR_R_OK;
}

int __check_blacklist(uid_t uid, const char *pkgid)
{
	static const char query[] =
		"SELECT * FROM blacklist "
		"WHERE idx=(SELECT idx FROM blacklist_index WHERE pkgid=?) "
		"AND uid=?";
	int ret;
	sqlite3 *db;
	sqlite3_stmt *stmt;

	db = _open_db();
	if (db == NULL)
		return PKGMGR_R_ERROR;

	ret = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		ERR("prepare error: %s", sqlite3_errmsg(db));
		sqlite3_close_v2(db);
		return PKGMGR_R_ERROR;
	}

	sqlite3_bind_text(stmt, 1, pkgid, -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 2, uid);

	ret = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if (ret != SQLITE_ROW) {
		if (ret == SQLITE_DONE)
			ERR("cannot find pkgid %s", pkgid);
		else
			ERR("step error: %s", sqlite3_errmsg(db));
		sqlite3_close_v2(db);
		return ret == SQLITE_DONE ? PKGMGR_R_ENOPKG : PKGMGR_R_ERROR;
	}

	sqlite3_close_v2(db);

	return PKGMGR_R_OK;
}
