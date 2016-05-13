#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <linux/limits.h>

#include <gdbm.h>

#include "pkgmgr-server.h"

#ifndef RUN_DIR
#define RUN_DIR "/run/user"
#endif
#define RESTRICTION_DB ".package_manager_restriction_mode"
#define VAL_SIZE sizeof(int)
#define ALL_PKG "ALL_PKG"

static char *__get_dbpath(uid_t uid)
{
	char buf[PATH_MAX];

	snprintf(buf, sizeof(buf), "%s/%d/%s", RUN_DIR, uid, RESTRICTION_DB);

	return strdup(buf);
}

static int __set_mode(int cur, int mode)
{
	return cur | mode;
}

static int __unset_mode(int cur, int mode)
{
	return cur & ~(mode);
}

static GDBM_FILE __open(const char *path, bool writable)
{
	GDBM_FILE db;

	db = gdbm_open((char *)path, 0, writable ? GDBM_WRCREAT : GDBM_READER,
			S_IRUSR | S_IWUSR, NULL);
	if (db == NULL)
		ERR("failed to open gdbm file(%s): %d", path, gdbm_errno);

	return db;
}

static void __close(GDBM_FILE dbf)
{
	gdbm_close(dbf);
}

static int __set_value(GDBM_FILE dbf, const char *pkgid, int mode)
{
	datum key;
	datum content;
	char buf[VAL_SIZE];

	key.dptr = (char *)pkgid;
	key.dsize = strlen(pkgid) + 1;

	memcpy(buf, &mode, VAL_SIZE);
	content.dptr = buf;
	content.dsize = VAL_SIZE;

	if (gdbm_store(dbf, key, content, GDBM_REPLACE)) {
		ERR("failed to store value");
		return -1;
	}

	return 0;
}

static int __get_value(GDBM_FILE dbf, const char *pkgid, int *mode)
{
	datum key;
	datum content;

	key.dptr = (char *)pkgid;
	key.dsize = strlen(pkgid) + 1;

	content = gdbm_fetch(dbf, key);
	if (content.dptr == NULL) {
		DBG("no value for key(%s)", pkgid);
		return -1;
	}

	if (content.dsize != VAL_SIZE)
		ERR("content size is different");

	memcpy(mode, content.dptr, VAL_SIZE);
	free(content.dptr);

	return 0;
}

int __restriction_mode_set(uid_t uid, const char *pkgid, int mode)
{
	GDBM_FILE dbf;
	char *dbpath;
	int cur = 0;

	if (pkgid == NULL || !strcmp(pkgid, ""))
		pkgid = ALL_PKG;

	dbpath = __get_dbpath(uid);
	if (dbpath == NULL)
		return -1;

	dbf = __open(dbpath, true);
	if (dbf == NULL) {
		free(dbpath);
		return -1;
	}

	__get_value(dbf, pkgid, &cur);
	mode = __set_mode(cur, mode);

	if (__set_value(dbf, pkgid, mode)) {
		free(dbpath);
		return -1;
	}

	__close(dbf);
	free(dbpath);

	return 0;
}

int __restriction_mode_unset(uid_t uid, const char *pkgid, int mode)
{
	GDBM_FILE dbf;
	char *dbpath;
	int cur = 0;

	if (pkgid == NULL || !strcmp(pkgid, ""))
		pkgid = ALL_PKG;

	dbpath = __get_dbpath(uid);
	if (dbpath == NULL)
		return -1;

	dbf = __open(dbpath, true);
	if (dbf == NULL) {
		free(dbpath);
		return -1;
	}

	__get_value(dbf, pkgid, &cur);
	mode = __unset_mode(cur, mode);

	if (__set_value(dbf, pkgid, mode)) {
		free(dbpath);
		return -1;
	}

	__close(dbf);
	free(dbpath);

	return 0;
}

int __restriction_mode_get(uid_t uid, const char *pkgid, int *mode)
{
	GDBM_FILE dbf;
	char *dbpath;

	if (pkgid == NULL || !strcmp(pkgid, ""))
		pkgid = ALL_PKG;

	dbpath = __get_dbpath(uid);
	if (dbpath == NULL)
		return -1;

	dbf = __open(dbpath, false);
	if (dbf == NULL) {
		if (gdbm_errno == GDBM_FILE_OPEN_ERROR) {
			*mode = 0;
			return 0;
		}
		free(dbpath);
		return -1;
	}

	if (__get_value(dbf, pkgid, mode)) {
		free(dbpath);
	}

	__close(dbf);
	free(dbpath);

	return 0;
}
