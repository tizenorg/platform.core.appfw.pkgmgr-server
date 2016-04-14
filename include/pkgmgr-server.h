/*
 * slp-pkgmgr
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
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

#ifndef _PKGMGR_SERVER_H_
#define _PKGMGR_SERVER_H_

#include <sys/types.h>
#include <glib.h>
#include <dlog.h>

#ifdef LOG_TAG
#undef LOG_TAG
#endif /* LOG_TAG */
#define LOG_TAG "PKGMGR_SERVER"

#ifndef ERR
#define ERR(fmt, args...) LOGE("[%s:%d] "fmt"\n", __func__, __LINE__, ##args)
#endif

#ifndef DBG
#define DBG(fmt, args...) LOGD("[%s:%d] "fmt"\n", __func__, __LINE__, ##args)
#endif

#ifndef INFO
#define INFO(fmt, args...) LOGI("[%s:%d] "fmt"\n", __func__, __LINE__, ##args)
#endif

#define CONF_FILE "/etc/package-manager/server/.config"
#define DESKTOP_FILE_DIRS "/usr/share/install-info/desktop.conf"

#define PKG_BACKEND "backend:"
#define PKG_CONF_PATH "/etc/package-manager/pkg_path.conf"

#define MAX_REQ_ID_LEN 256
#define MAX_PKG_TYPE_LEN 128
#define MAX_PKG_NAME_LEN 256
#define MAX_PKG_ARGS_LEN 4096
#define DESKTOP_FILE_DIRS_NUM 1024

enum request_type {
	PKGMGR_REQUEST_TYPE_INSTALL,
	PKGMGR_REQUEST_TYPE_REINSTALL,
	PKGMGR_REQUEST_TYPE_UNINSTALL,
	PKGMGR_REQUEST_TYPE_MOVE,
	PKGMGR_REQUEST_TYPE_ENABLE_PKG,
	PKGMGR_REQUEST_TYPE_DISABLE_PKG,
	PKGMGR_REQUEST_TYPE_ENABLE_APP,
	PKGMGR_REQUEST_TYPE_DISABLE_APP,
	PKGMGR_REQUEST_TYPE_GETSIZE,
	PKGMGR_REQUEST_TYPE_CLEARDATA,
	PKGMGR_REQUEST_TYPE_CLEARCACHE,
	PKGMGR_REQUEST_TYPE_ENABLE_GLOBAL_APP_FOR_UID,
	PKGMGR_REQUEST_TYPE_DISABLE_GLOBAL_APP_FOR_UID,
	PKGMGR_REQUEST_TYPE_KILL,
	PKGMGR_REQUEST_TYPE_CHECK,
	PKGMGR_REQUEST_TYPE_GENERATE_LICENSE_REQUEST,
	PKGMGR_REQUEST_TYPE_REGISTER_LICENSE,
	PKGMGR_REQUEST_TYPE_DECRYPT_PACKAGE,
	PKGMGR_REQUEST_TYPE_ADD_BLACKLIST,
	PKGMGR_REQUEST_TYPE_REMOVE_BLACKLIST,
	PKGMGR_REQUEST_TYPE_CHECK_BLACKLIST,
	PKGMGR_REQUEST_TYPE_ENABLE_APP_SPLASH_SCREEN,
	PKGMGR_REQUEST_TYPE_DISABLE_APP_SPLASH_SCREEN,
	PKGMGR_REQUEST_TYPE_ENABLE_GLOBAL_APP_SPLASH_SCREEN_FOR_UID,
	PKGMGR_REQUEST_TYPE_DISABLE_GLOBAL_APP_SPLASH_SCREEN_FOR_UID,
};

typedef struct {
	char req_id[MAX_REQ_ID_LEN];
	int req_type;
	uid_t uid;
	char pkg_type[MAX_PKG_TYPE_LEN];
	char pkgid[MAX_PKG_NAME_LEN];
	char appid[MAX_PKG_NAME_LEN];
	char args[MAX_PKG_ARGS_LEN];
} pm_dbus_msg;

typedef struct backend_info_t {
	int pid;
	uid_t uid;
	char pkgtype[MAX_PKG_TYPE_LEN];
	char pkgid[MAX_PKG_NAME_LEN];
	char args[MAX_PKG_ARGS_LEN];
} backend_info;

char *_get_backend_cmd(char *type);

gboolean queue_job(void *data);
int __return_value_to_caller(const char *req_key, GVariant *result);
int __init_request_handler(void);
void __fini_request_handler(void);
int __add_blacklist(uid_t uid, const char *pkgid);
int __remove_blacklist(uid_t uid, const char *pkgid);
int __check_blacklist(uid_t uid, const char *pkgid, int *result);

#endif/*  _PKGMGR_SERVER_H_ */
