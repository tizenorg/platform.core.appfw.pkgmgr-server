/*
 * Copyright (c) 2000 - 2016 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Jayoun Lee <airjany@samsung.com>, Sewook Park <sewook7.park@samsung.com>,
 * Jaeho Lee <jaeho81.lee@samsung.com>, Shobhit Srivastava <shobhit.s@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include <sqlite3.h>

#include <package-manager.h>
#include <package-manager-debug.h>

#include "pkgmgr-server.h"

static const char *_get_db_path(void)
{
	return LOCAL_STATE_DIR"/package-manager/blacklist.db";
}

static sqlite3 *_open_db(void)
{
	int ret;
	const char *path;
	sqlite3 *db;

	path = _get_db_path();
	if (path == NULL) {
		ERR("get db path error");
		return NULL;
	}

	ret = sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL);
	if (ret != SQLITE_OK) {
		ERR("open db error: %d", ret);
		return NULL;
	}

	return db;
}

static int __add_blacklist_info(sqlite3 *db, uid_t uid, const char *pkgid)
{
	static const char query[] =
		"INSERT INTO blacklist (uid, pkgid) VALUES(?, ?)";
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

	return PKGMGR_R_OK;
}

static int __remove_blacklist_info(sqlite3 *db, uid_t uid, const char *pkgid)
{
	static const char query[] =
		"DELETE FROM blacklist WHERE uid=? AND pkgid=?";
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

int __check_blacklist(uid_t uid, const char *pkgid, int *result)
{
	static const char query[] =
		"SELECT * FROM blacklist WHERE uid=? AND pkgid=?";
	int ret;
	sqlite3 *db;
	sqlite3_stmt *stmt;

	db = _open_db();
	if (db == NULL) {
		*result = 0;
		return PKGMGR_R_ERROR;
	}

	ret = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		ERR("prepare error: %s", sqlite3_errmsg(db));
		*result = 0;
		sqlite3_close_v2(db);
		return PKGMGR_R_ERROR;
	}

	sqlite3_bind_int(stmt, 1, uid);
	sqlite3_bind_text(stmt, 2, pkgid, -1, SQLITE_STATIC);

	ret = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if (ret != SQLITE_ROW) {
		if (ret != SQLITE_DONE)
			ERR("step error: %s", sqlite3_errmsg(db));
		*result = 0;
		sqlite3_close_v2(db);
		return ret == SQLITE_DONE ? PKGMGR_R_OK : PKGMGR_R_ERROR;
	}

	*result = 1;
	sqlite3_close_v2(db);

	return PKGMGR_R_OK;
}
