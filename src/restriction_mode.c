#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/limits.h>

#include <sqlite3.h>

#include "pkgmgr-server.h"

#ifndef RUN_DIR
#define RUN_DIR "/run/user"
#endif
#ifndef DB_DIR
#define DB_DIR "/var/lib/package-manager"
#endif
#define RESTRICTION_CONF ".package_manager_restriction_mode"
#define BUFSIZE 4096

static int __set_mode(int cur, int mode)
{
	return cur | mode;
}

static int __unset_mode(int cur, int mode)
{
	return cur & ~(mode);
}

static char *__get_conf_file_path(uid_t uid)
{
	char buf[PATH_MAX];

	snprintf(buf, sizeof(buf), "%s/%d/%s", RUN_DIR, uid, RESTRICTION_CONF);

	return strdup(buf);
}

static int __set_restriction_mode(uid_t uid, int mode)
{
	char *conf_path;
	int fd;
	int cur = 0;
	ssize_t len;

	conf_path = __get_conf_file_path(uid);
	if (conf_path == NULL) {
		ERR("failed to get conf path");
		return -1;
	}

	fd = open(conf_path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		ERR("failed to open conf file: %d", errno);
		free(conf_path);
		return -1;
	}

	len = read(fd, &cur, sizeof(int));
	if (len < 0) {
		ERR("failed to read conf file: %d", errno);
		close(fd);
		free(conf_path);
		return -1;
	}

	mode = __set_mode(cur, mode);

	lseek(fd, 0, SEEK_SET);
	len = write(fd, &mode, sizeof(int));
	if (len < 0) {
		ERR("failed to write conf file: %d", errno);
		close(fd);
		free(conf_path);
		return -1;
	}

	close(fd);
	free(conf_path);

	return 0;
}

static int __unset_restriction_mode(uid_t uid, int mode)
{
	char *conf_path;
	int fd;
	int cur = 0;
	ssize_t len;

	conf_path = __get_conf_file_path(uid);
	if (conf_path == NULL) {
		ERR("failed to get conf path");
		return -1;
	}

	if (access(conf_path, F_OK) != 0) {
		free(conf_path);
		return 0;
	}

	fd = open(conf_path, O_RDWR, 0);
	if (fd < 0) {
		ERR("failed to open conf file: %s", errno);
		free(conf_path);
		return -1;
	}

	len = read(fd, &cur, sizeof(int));
	if (len < 0) {
		ERR("failed to read conf file: %d", errno);
		close(fd);
		free(conf_path);
		return -1;
	}

	mode = __unset_mode(cur, mode);

	lseek(fd, 0, SEEK_SET);
	len = write(fd, &mode, sizeof(int));
	if (len < 0) {
		ERR("failed to write conf file: %d", errno);
		close(fd);
		free(conf_path);
		return -1;
	}

	close(fd);
	free(conf_path);

	return 0;
}

static int __get_restriction_mode(uid_t uid, int *mode)
{
	char *conf_path;
	int fd;
	int cur;
	ssize_t len;

	conf_path = __get_conf_file_path(uid);
	if (conf_path == NULL)
		return -1;

	if (access(conf_path, F_OK) != 0) {
		free(conf_path);
		*mode = 0;
		return 0;
	}

	fd = open(conf_path, O_RDONLY, 0);
	if (fd < 0) {
		ERR("failed to open conf file: %s", errno);
		free(conf_path);
		return -1;
	}

	len = read(fd, &cur, sizeof(int));
	if (len < 0) {
		ERR("failed to read conf file: %d", errno);
		close(fd);
		free(conf_path);
		return -1;
	}

	*mode = cur;

	close(fd);
	free(conf_path);

	return 0;
}

static const char *__get_db_path(void)
{
	return DB_DIR"/restriction.db";
}

static sqlite3 *__open_db(void)
{
	int ret;
	const char *path;
	sqlite3 *db;

	path = __get_db_path();
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

enum {
	TYPE_SET,
	TYPE_UNSET,
};

static int __update_pkg_restriction_mode(uid_t uid, const char *pkgid, int mode,
		int type)
{
	static const char query[] =
		"INSERT OR REPLACE INTO restriction (uid, pkgid, mode) "
		"VALUES(?, ?, (COALESCE("
		" (SELECT mode FROM restriction WHERE uid=? AND pkgid=?), 0) ";
	int ret;
	sqlite3 *db;
	sqlite3_stmt *stmt;
	char buf[BUFSIZE];

	db = __open_db();
	if (db == NULL)
		return -1;

	snprintf(buf, sizeof(buf), "%s%s", query,
			type == TYPE_SET ? "| ?))" : "& ~?))");

	ret = sqlite3_prepare_v2(db, buf, strlen(buf), &stmt, NULL);
	if (ret != SQLITE_OK) {
		ERR("prepare error: %s", sqlite3_errmsg(db));
		sqlite3_close_v2(db);
		return -1;
	}

	sqlite3_bind_int(stmt, 1, uid);
	sqlite3_bind_text(stmt, 2, pkgid, -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 3, uid);
	sqlite3_bind_text(stmt, 4, pkgid, -1, SQLITE_STATIC);
	sqlite3_bind_int(stmt, 5, mode);

	ret = sqlite3_step(stmt);
	sqlite3_finalize(stmt);
	if (ret != SQLITE_DONE) {
		ERR("step error: %s", sqlite3_errmsg(db));
		sqlite3_close_v2(db);
		return -1;
	}

	sqlite3_close_v2(db);

	return 0;
}

static int __get_pkg_restriction_mode(uid_t uid, const char *pkgid, int *mode)
{
	static const char query[] =
		"SELECT COALESCE( "
		" (SELECT mode FROM restriction WHERE uid=? AND pkgid=?), 0)";
	int ret;
	sqlite3 *db;
	sqlite3_stmt *stmt;

	db = __open_db();
	if (db == NULL) {
		return -1;
	}

	ret = sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL);
	if (ret != SQLITE_OK) {
		ERR("prepare error: %s", sqlite3_errmsg(db));
		sqlite3_close_v2(db);
		return -1;
	}

	sqlite3_bind_int(stmt, 1, uid);
	sqlite3_bind_text(stmt, 2, pkgid, -1, SQLITE_STATIC);

	ret = sqlite3_step(stmt);
	if (ret != SQLITE_ROW) {
		ERR("step error: %s", sqlite3_errmsg(db));
		sqlite3_finalize(stmt);
		sqlite3_close_v2(db);
		return -1;
	}

	*mode = sqlite3_column_int(stmt, 0);

	sqlite3_finalize(stmt);
	sqlite3_close_v2(db);

	return 0;
}

int _restriction_mode_set(uid_t uid, const char *pkgid, int mode)
{
	if (pkgid && strlen(pkgid))
		return __update_pkg_restriction_mode(uid, pkgid, mode,
				TYPE_SET);
	else
		return __set_restriction_mode(uid, mode);
}

int _restriction_mode_unset(uid_t uid, const char *pkgid, int mode)
{
	if (pkgid && strlen(pkgid))
		return __update_pkg_restriction_mode(uid, pkgid, mode,
				TYPE_UNSET);
	else
		return __unset_restriction_mode(uid, mode);
}

int _restriction_mode_get(uid_t uid, const char *pkgid, int *mode)
{
	if (pkgid && strlen(pkgid))
		return __get_pkg_restriction_mode(uid, pkgid, mode);
	else
		return __get_restriction_mode(uid, mode);
}
