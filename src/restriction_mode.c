/*
 * Copyright (c) 2016 Samsung Electronics Co., Ltd. All rights reserved.
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/limits.h>

#include "pkgmgr-server.h"

#ifndef RUN_DIR
#define RUN_DIR "/run/user"
#endif

#define RESTRICTION_CONF ".package_manager_restriction_mode"

static char *_get_conf_file_path(uid_t uid)
{
	char buf[PATH_MAX];

	snprintf(buf, sizeof(buf), "%s/%d/%s", RUN_DIR, uid, RESTRICTION_CONF);

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

int __set_restriction_mode(uid_t uid, int mode)
{
	char *conf_path;
	int fd;
	int cur = 0;
	ssize_t len;

	conf_path = _get_conf_file_path(uid);
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

int __unset_restriction_mode(uid_t uid, int mode)
{
	char *conf_path;
	int fd;
	int cur = 0;
	ssize_t len;

	conf_path = _get_conf_file_path(uid);
	if (conf_path == NULL) {
		ERR("failed to get conf path");
		return -1;
	}

	if (access(conf_path, F_OK) != 0) {
		ERR("restriction mode is not set");
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

int __get_restriction_mode(uid_t uid, int *result)
{
	char *conf_path;
	int fd;
	int cur;
	ssize_t len;

	conf_path = _get_conf_file_path(uid);
	if (conf_path == NULL)
		return -1;

	if (access(conf_path, F_OK) != 0) {
		free(conf_path);
		*result = 0;
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

	*result = cur;

	close(fd);
	free(conf_path);

	return 0;
}
