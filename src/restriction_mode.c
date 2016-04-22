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
#define RUN_DIR "/var/run/user"
#endif

#define RESTRICTION_CONF ".package_manager_restriction_mode"

static char *_get_conf_file_path(uid_t uid)
{
	char buf[PATH_MAX];

	snprintf(buf, sizeof(buf), "%s/%d/%s", RUN_DIR, uid, RESTRICTION_CONF);

	return strdup(buf);
}

int __set_restriction_mode(uid_t uid)
{
	char *conf_path;
	int fd;

	conf_path = _get_conf_file_path(uid);
	if (conf_path == NULL) {
		ERR("failed to get conf path");
		return -1;
	}

	if (access(conf_path, F_OK) == 0) {
		ERR("restriction mode is already set");
		free(conf_path);
		return 0;
	}

	fd = open(conf_path, O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		ERR("failed to create conf file: %s", strerror(errno));
		free(conf_path);
		return -1;
	}

	close(fd);
	free(conf_path);

	return 0;
}

int __unset_restriction_mode(uid_t uid)
{
	char *conf_path;

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

	if (unlink(conf_path)) {
		free(conf_path);
		return -1;
	}

	free(conf_path);

	return 0;
}

int __check_restriction_mode(uid_t uid, int *result)
{
	char *conf_path;

	conf_path = _get_conf_file_path(uid);
	if (conf_path == NULL)
		return -1;

	if (access(conf_path, F_OK) != 0)
		*result = 0;
	else
		*result = 1;

	free(conf_path);

	return 0;
}
