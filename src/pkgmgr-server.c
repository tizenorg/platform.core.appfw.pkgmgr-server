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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <grp.h>

#include <glib.h>
#include <gio/gio.h>

#include <pkgmgr-info.h>
#include <pkgmgr/pkgmgr_parser_db.h>
#include <tzplatform_config.h>
#include <drm-tizen-apps.h>

#include "pkgmgr_installer.h"
#include "pkgmgr-server.h"
#include "pm-queue.h"
#include "package-manager.h"

#define BUFMAX 128
#define NO_MATCHING_FILE 11

#define OWNER_ROOT 0
#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)

#define EXT_STORAGE_GROUP 10001
#define EXT_STORAGE_APPDATA_GROUP 10002
#define MEDIA_STORAGE_GROUP 10502
#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

typedef struct  {
	char **env;
	uid_t uid;
	gid_t gid;
} user_ctx;

typedef struct {
	uid_t uid;
	char *cmd;
} pkgcmd_data;

/*
8 bit value to represent maximum 8 backends.
Each bit position corresponds to a queue slot which
is dynamically determined.
*/
char backend_busy = 0;
extern int num_of_backends;

struct signal_info_t {
	pid_t pid;
	int status;
};

static int pipe_sig[2];
static GIOChannel *pipe_io;
static guint pipe_wid;

backend_info *begin;
extern queue_info_map *start;
extern int entries;

GMainLoop *mainloop = NULL;


/* operation_type */
typedef enum {
	OPERATION_INSTALL = 0,
	OPERATION_UNINSTALL,
	OPERATION_ACTIVATE,
	OPERATION_REINSTALL,
	OPERATION_MAX
} OPERATION_TYPE;

static int __check_backend_status_for_exit(void);
static int __check_queue_status_for_exit(void);
static int __is_backend_busy(int position);
static void __set_backend_busy(int position);
static void __set_backend_free(int position);
static void sighandler(int signo);

gboolean exit_server(void *data);

/* To check whether a particular backend is free/busy*/
static int __is_backend_busy(int position)
{
	return backend_busy & 1<<position;
}
/*To set a particular backend as busy*/
static void __set_backend_busy(int position)
{
	backend_busy = backend_busy | 1<<position;
}
/*To set a particular backend as free */
static void __set_backend_free(int position)
{
	backend_busy = backend_busy & ~(1<<position);
}

static void __send_app_signal(uid_t uid, const char *req_id,
		const char *pkgid, const char *appid,
		const char *key, const char *val, int req_type)
{
	pkgmgr_installer *pi;

	pi = pkgmgr_installer_new();
	if (!pi) {
		DBG("Failure in creating the pkgmgr_installer object");
		return;
	}

	if (pkgmgr_installer_set_uid(pi, uid))
		goto catch;

	switch (req_type) {
	case PKGMGR_REQUEST_TYPE_ENABLE_GLOBAL_APP_FOR_UID:
	case PKGMGR_REQUEST_TYPE_ENABLE_APP:
		if (pkgmgr_installer_set_request_type(pi, PKGMGR_REQ_ENABLE_APP))
			goto catch;
		break;
	case PKGMGR_REQUEST_TYPE_DISABLE_GLOBAL_APP_FOR_UID:
	case PKGMGR_REQUEST_TYPE_DISABLE_APP:
		if (pkgmgr_installer_set_request_type(pi, PKGMGR_REQ_DISABLE_APP))
			goto catch;
		break;
	case PKGMGR_REQUEST_TYPE_ENABLE_APP_SPLASH_SCREEN:
		if (pkgmgr_installer_set_request_type(pi, PKGMGR_REQ_ENABLE_APP_SPLASH_SCREEN))
			goto catch;
		break;
	case PKGMGR_REQUEST_TYPE_DISABLE_APP_SPLASH_SCREEN:
		if (pkgmgr_installer_set_request_type(pi, PKGMGR_REQ_DISABLE_APP_SPLASH_SCREEN))
			goto catch;
		break;
	default:
		DBG("Unsupported req_type[%d]", req_type);
		goto catch;
	}

	if (pkgmgr_installer_set_session_id(pi, req_id))
		goto catch;
	pkgmgr_installer_send_app_signal(pi, "app", pkgid, appid, key, val);

catch:
	pkgmgr_installer_free(pi);

	return;
}

static void __send_fail_signal(backend_info *info)
{
	int req_type;
	pkgmgr_installer *pi;
	pi = pkgmgr_installer_new();
	if (!pi) {
		ERR("Failure in creating the pkgmgr_installer object");
		return;
	}
	pkgmgr_installer_set_session_id(pi, info->req_id);
	switch(info->req_type) {
	case PKGMGR_REQUEST_TYPE_INSTALL:
	case PKGMGR_REQUEST_TYPE_MOUNT_INSTALL:
	case PKGMGR_REQUEST_TYPE_REINSTALL:
		req_type = PKGMGR_REQ_INSTALL;
		break;
	case PKGMGR_REQUEST_TYPE_UNINSTALL:
		req_type = PKGMGR_REQ_UNINSTALL;
		break;
	case PKGMGR_REQUEST_TYPE_MOVE:
		req_type = PKGMGR_REQ_MOVE;
		break;
	case PKGMGR_REQUEST_TYPE_GETSIZE:
		req_type = PKGMGR_REQ_GETSIZE;
		break;
	default:
		req_type = PKGMGR_REQ_INVALID;
		break;
	}
	pkgmgr_installer_set_request_type(pi, req_type);
	pkgmgr_installer_send_signal(pi, info->pkgtype, info->pkgid, "end", "fail");
	pkgmgr_installer_free(pi);
	return;
}

static gboolean pipe_io_handler(GIOChannel *io, GIOCondition cond, gpointer data)
{
	int x;
	GError *err = NULL;
	GIOStatus s;
	gsize len;
	struct signal_info_t info;
	backend_info *ptr = begin;

	s = g_io_channel_read_chars(io, (gchar *)&info, sizeof(struct signal_info_t), &len, &err);
	if (s != G_IO_STATUS_NORMAL) {
		ERR("Signal pipe read failed: %s", err->message);
		g_error_free(err);
		return TRUE;
	}

	for (x = 0; x < num_of_backends; x++, ptr++) {
		if (ptr && ptr->pid == info.pid)
			break;
	}

	if (x == num_of_backends) {
		ERR("Unknown child exit");
		return -1;
	}

	__set_backend_free(x);
	if (WIFSIGNALED(info.status)) {
		__send_fail_signal(ptr);
		DBG("backend[%s] exit with signal[%d]", ptr->pkgtype,
				WTERMSIG(info.status));
	} else if (WEXITSTATUS(info.status)) {
		DBG("backend[%s] exit with error", ptr->pkgtype);
	} else {
		DBG("backend[%s] exit", ptr->pkgtype);
	}

	g_idle_add(queue_job, NULL);

	return TRUE;
}

static int __init_backend_info(void)
{
	backend_info *ptr;

	/*Allocate memory for holding pid, pkgtype and pkgid*/
	ptr = (backend_info*)calloc(num_of_backends, sizeof(backend_info));
	if (ptr == NULL) {
		DBG("Malloc Failed\n");
		return -1;
	}
	begin = ptr;

	if (pipe(pipe_sig)) {
		ERR("create pipe failed");
		return -1;
	}

	pipe_io = g_io_channel_unix_new(pipe_sig[0]);
	g_io_channel_set_encoding(pipe_io, NULL, NULL);
	g_io_channel_set_buffered(pipe_io, FALSE);
	pipe_wid = g_io_add_watch(pipe_io, G_IO_IN, pipe_io_handler, NULL);

	return 0;
}

static void __fini_backend_info(void)
{
	g_source_remove(pipe_wid);
	g_io_channel_unref(pipe_io);
	close(pipe_sig[0]);
	close(pipe_sig[1]);

	/*Free backend info */
	free(begin);
}

static void sighandler(int signo)
{
	struct signal_info_t info;
	char buf[1024] = {0, };

	info.pid = waitpid(-1, &info.status, WNOHANG);
	if (write(pipe_sig[1], &info, sizeof(struct signal_info_t)) < 0)
		ERR("failed to write result: %s", strerror_r(errno, buf, sizeof(buf)));
}

static int __register_signal_handler(void)
{
	static int sig_reg = 0;
	struct sigaction act;

	if (sig_reg)
		return 0;

	act.sa_handler = sighandler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_NOCLDSTOP;
	if (sigaction(SIGCHLD, &act, NULL) < 0) {
		ERR("signal: SIGCHLD failed\n");
		return -1;
	}

	g_timeout_add_seconds(2, exit_server, NULL);

	sig_reg = 1;
	return 0;
}

static int __check_backend_status_for_exit(void)
{
	int i = 0;
	for(i = 0; i < num_of_backends; i++)
	{
		if (!__is_backend_busy(i))
			continue;
		else
			return 0;
	}
	return 1;
}

static int __check_queue_status_for_exit(void)
{
	pm_queue_data *head[MAX_QUEUE_NUM] = {NULL,};
	queue_info_map *ptr = NULL;
	ptr = start;
	int i = 0;
	int c = 0;
	int slot = -1;
	for(i = 0; i < entries; i++)
	{
		if (ptr->queue_slot <= slot) {
			ptr++;
			continue;
		}
		else {
			head[c] = ptr->head;
			slot = ptr->queue_slot;
			c++;
			ptr++;
		}
	}
	for(i = 0; i < num_of_backends; i++)
	{
		if (!head[i])
			continue;
		else
			return 0;
	}
	return 1;
}

gboolean exit_server(void *data)
{
	DBG("exit_server Start\n");
	if (__check_backend_status_for_exit() &&
			__check_queue_status_for_exit()) {
		if (!getenv("PMS_STANDALONE")) {
			g_main_loop_quit(mainloop);
			return FALSE;
		}
	}
	return TRUE;
}

static int __pkgcmd_read_proc(const char *path, char *buf, int size)
{
	int fd;
	int ret;
	if (buf == NULL || path == NULL)
		return -1;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	ret = read(fd, buf, size - 1);
	if (ret <= 0) {
		close(fd);
		return -1;
	} else
		buf[ret] = 0;
	close(fd);
	return ret;
}

static int __pkgcmd_find_pid_by_cmdline(const char *dname,
			const char *cmdline, const char *apppath)
{
	int pid = 0;
	int pgid = 0;

	if (strcmp(cmdline, apppath) == 0) {
		pid = atoi(dname);
		pgid = getpgid(pid);
		if (pgid < 0) {
			ERR("getpgid failed, errno(%d)", errno);
			pid = 0;
		}
		if (pid != pgid)
			pid = 0;
	}
	return pid;
}

static int __pkgcmd_proc_iter_kill_cmdline(const char *apppath, int option)
{
	DIR *dp;
	struct dirent dentry, *result;
	int pid;
	int ret;
	char buf[1024] = {'\0'};
	int pgid;

	dp = opendir("/proc");
	if (dp == NULL) {
		return -1;
	}

	for (ret = readdir_r(dp, &dentry, &result);
			ret == 0 && result != NULL;
			ret = readdir_r(dp, &dentry, &result)) {
		if (!isdigit(dentry.d_name[0]))
			continue;

		snprintf(buf, sizeof(buf), "/proc/%s/cmdline", dentry.d_name);
		ret = __pkgcmd_read_proc(buf, buf, sizeof(buf));
		if (ret <= 0)
			continue;

		pid = __pkgcmd_find_pid_by_cmdline(dentry.d_name, buf, apppath);
		if (pid > 0) {
			if (option == 0) {
				closedir(dp);
				return pid;
			}
			pgid = getpgid(pid);
			if (pgid <= 1) {
				closedir(dp);
				ERR("getpgid failed, errno(%d)", errno);
				return -1;
			}
			if (killpg(pgid, SIGKILL) < 0) {
				closedir(dp);
				ERR("killpg failed, errno(%d)", errno);
				return -1;
			}
			closedir(dp);
			return pid;
		}
	}
	closedir(dp);
	return 0;
}

static void __make_pid_info_file(char *req_key, int pid, uid_t uid)
{
	FILE* file;
	int fd;
	int ret;
	char buf[MAX_PKG_TYPE_LEN] = {0};
	char info_file[PATH_MAX] = {'\0'};
	struct passwd pwd;
	struct passwd *pwd_result;

	if(req_key == NULL)
		return;

	ret = getpwuid_r(uid, &pwd, buf, sizeof(buf), &pwd_result);
	if (ret != 0 || pwd_result == NULL) {
		ERR("get uid failed(%d) for user(%d)", ret, uid);
		return;
	}
	DBG("uid(%d), gid(%d)", uid, pwd.pw_gid);

	snprintf(info_file, PATH_MAX, "/tmp/pkgmgr/%s", req_key);

	DBG("info_path(%s)", info_file);
	file = fopen(info_file, "w");
	if (file == NULL) {
		ERR("Couldn't open the file(%s)", info_file);
		return;
	}

	snprintf(buf, MAX_PKG_TYPE_LEN, "%d\n", pid);
	fwrite(buf, 1, strlen(buf), file);

	fflush(file);
	fd = fileno(file);
	if (fchmod(fd, 0777) < 0)
		ERR("chmod failed, errno(%d)", errno);
	if (fchown(fd, uid, pwd.pw_gid) < 0)
		ERR("chown failed, errno(%d)", errno);
	fsync(fd);
	fclose(file);
}

static int __kill_app(char *appid, uid_t uid)
{
	pkgmgrinfo_appinfo_h appinfo;
	int ret = PMINFO_R_ERROR;
	char *exec = NULL;

	ret = pkgmgrinfo_appinfo_get_usr_appinfo(appid, uid, &appinfo);
	if (ret != PMINFO_R_OK)
		return PMINFO_R_ERROR;

	ret = pkgmgrinfo_appinfo_get_exec(appinfo, &exec);
	if (ret != PMINFO_R_OK) {
		pkgmgrinfo_appinfo_destroy_appinfo(appinfo);
		return PMINFO_R_ERROR;
	}

	ret = __pkgcmd_proc_iter_kill_cmdline(exec, 1);
	if (ret != PMINFO_R_OK) {
		DBG("failed to kill app[%s], exec[%s]", appid, exec);
	}

	pkgmgrinfo_appinfo_destroy_appinfo(appinfo);
	return ret;
}

static int __pkgcmd_app_cb(const pkgmgrinfo_appinfo_h handle, void *user_data)
{
	char *pkgid;
	char *exec;
	int ret;
	int pid = -1;
	pkgcmd_data *pdata = (pkgcmd_data *)user_data;

	if (handle == NULL) {
		perror("appinfo handle is NULL\n");
		exit(1);
	}
	ret = pkgmgrinfo_appinfo_get_exec(handle, &exec);
	if (ret) {
		perror("Failed to get app exec path\n");
		exit(1);
	}
	ret = pkgmgrinfo_appinfo_get_pkgid(handle, &pkgid);
	if (ret) {
		perror("Failed to get pkgid\n");
		exit(1);
	}

	if (strcmp(pdata->cmd, "kill") == 0)
		pid = __pkgcmd_proc_iter_kill_cmdline(exec, 1);
	else if(strcmp(pdata->cmd, "check") == 0)
		pid = __pkgcmd_proc_iter_kill_cmdline(exec, 0);

	__make_pid_info_file(pkgid, pid, pdata->uid);

	return 0;
}

void free_user_context(user_ctx* ctx)
{
	char **env = NULL;
	int i = 0;
	if (!ctx)
		return;
	env = ctx->env;
	//env variable ends by NULL element
	while (env[i]) {
		free(env[i]);
		i++;
	}
	free(env);
	env = NULL;
	free(ctx);
}

int set_environement(user_ctx *ctx)
{
	int i = 0;
	int res = 0;
	char **env = NULL;
	gid_t groups[] = {EXT_STORAGE_GROUP,
		EXT_STORAGE_APPDATA_GROUP,
		MEDIA_STORAGE_GROUP};

	if (!ctx)
		return -1;;
	if (setgid(ctx->gid)) {
		ERR("setgid failed: %d", errno);
		return -1;
	}
	if (setgroups(ARRAY_SIZE(groups), groups) < 0) {
		ERR("setgroups failed: %d", errno);
		return -1;
	}
	if (setuid(ctx->uid)) {
		ERR("setuid failed: %d", errno);
		return -1;
	}
	env = ctx->env;
	//env variable ends by NULL element
	while (env[i]) {
		if (putenv(env[i]) != 0)
			res = -1;
		i++;
	}
	return res;
}

user_ctx *get_user_context(uid_t uid)
{
	/* we can use getpwnam because this is used only after a
	 * fork and just before an execv
	 * No concurrencial call can corrupt the data
	 * returned by getpwuid
	 */
	user_ctx *context_res;
	char **env = NULL;
	char buf[1024] = {0, };
	struct passwd pwd, *result;
	int len;
	int ret = 0;
	int i;

	ret = getpwuid_r(uid, &pwd, buf, sizeof(buf), &result);
	if (ret != 0 || result == NULL)
		return NULL;

	do {
		context_res = (user_ctx *)malloc(sizeof(user_ctx));
		if (!context_res) {
			ret = -1;
			break;
		}
		env = (char **)malloc(3 * sizeof(char *));
		if (!env) {
			ret = -1;
			break;
		}
		// Build environment context
		DBG("jungh pw_dir is [%s]", pwd.pw_dir);
		DBG("jungh pw_dir is [%s]", pwd.pw_name);
		len = snprintf(NULL, 0, "HOME=%s", pwd.pw_dir);
		env[0] = (char *)malloc((len + 1) * sizeof(char));
		if(env[0] == NULL) {
			ret = -1;
			break;
		}
		snprintf(env[0], len + 1, "HOME=%s", pwd.pw_dir);
		len = snprintf(NULL, 0, "USER=%s", pwd.pw_name);
		env[1] = (char *)malloc((len + 1) * sizeof(char));
		if(env[1] == NULL) {
			ret = -1;
			break;
		}
		snprintf(env[1], len + 1, "USER=%s", pwd.pw_name);
		env[2] = NULL;
	} while (0);

	if (ret == -1) {
		free(context_res);
		context_res = NULL;
		i = 0;
		//env variable ends by NULL element
		while (env && env[i]) {
			free(env[i]);
			i++;
		}
		free(env);
		env = NULL;
	} else {
		context_res->env = env;
		context_res->uid = uid;
		context_res->gid = pwd.pw_gid;
	}
	return context_res;
}

static char **__generate_argv(const char *args)
{
	/* Create args vector
	 * req_id + pkgid + args
	 *
	 * vector size = # of args +
	 *(req_id + pkgid + NULL termination = 3)
	 * Last value must be NULL for execv.
	 */
	gboolean ret_parse;
	gint argcp;
	gchar **argvp;
	GError *gerr = NULL;
	int i;

	ret_parse = g_shell_parse_argv(args, &argcp, &argvp, &gerr);
	if (FALSE == ret_parse) {
		DBG("Failed to split args: %s", args);
		DBG("messsage: %s", gerr->message);
		exit(1);
	}

	/* dbg */
	for (i = 0; i < argcp; i++)
		DBG(">>>>>> argsv[%d]=%s", i, argvp[i]);

	return argvp;
}

void __set_environment(gpointer user_data)
{
	user_ctx *ctx = (user_ctx *)user_data;

	if (set_environement(ctx))
		DBG("Failed to set env for the user : %d", ctx->uid);
}

static int __fork_and_exec_with_args(char **argv, uid_t uid)
{
	user_ctx* user_context;
	GError *error = NULL;
	gboolean ret;
	int pid;

	user_context = get_user_context((uid_t)301); // jungh.yeon temp fix to 301 for app_fw user
	if (!user_context) {
		DBG("Failed to getenv for the user : %d", 301);
		return -1;
	}

	ret = g_spawn_async(NULL, argv, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
			__set_environment, (gpointer)user_context, &pid,
			&error);
	if (ret != TRUE) {
		ERR("Failed to excute backend: %s", error->message);
		g_error_free(error);
	}

	free_user_context(user_context);

	return pid;
}

static int __change_item_info(pm_dbus_msg *item, uid_t uid, bool *is_global)
{
	int ret = 0;
	char *pkgid = NULL;
	pkgmgrinfo_appinfo_h handle = NULL;

	switch (item->req_type) {
	case PKGMGR_REQUEST_TYPE_DISABLE_APP:
	case PKGMGR_REQUEST_TYPE_DISABLE_GLOBAL_APP_FOR_UID:
	case PKGMGR_REQUEST_TYPE_ENABLE_APP_SPLASH_SCREEN:
	case PKGMGR_REQUEST_TYPE_DISABLE_APP_SPLASH_SCREEN:
		ret = pkgmgrinfo_appinfo_get_usr_appinfo(item->pkgid, uid, &handle);
		break;
	case PKGMGR_REQUEST_TYPE_ENABLE_APP:
	case PKGMGR_REQUEST_TYPE_ENABLE_GLOBAL_APP_FOR_UID:
		ret = pkgmgrinfo_appinfo_get_usr_disabled_appinfo(item->pkgid, uid, &handle);
		break;
	default:
		return PMINFO_R_ERROR;
	}

	if (ret != PMINFO_R_OK)
		return PMINFO_R_ERROR;

	ret = pkgmgrinfo_appinfo_is_global(handle, is_global);
	if (ret != PMINFO_R_OK)
		goto catch;

	if ((item->req_type == PKGMGR_REQUEST_TYPE_DISABLE_APP
			|| item->req_type == PKGMGR_REQUEST_TYPE_ENABLE_APP)
			&& *is_global) {
			ret = PMINFO_R_ERROR;
			goto catch;
	} else if ((item->req_type == PKGMGR_REQUEST_TYPE_DISABLE_GLOBAL_APP_FOR_UID
			|| item->req_type == PKGMGR_REQUEST_TYPE_ENABLE_GLOBAL_APP_FOR_UID)
			&& !*is_global) {
			ret = PMINFO_R_ERROR;
			goto catch;
	}

	ret = pkgmgrinfo_appinfo_get_pkgid(handle, &pkgid);
	if (ret != PMINFO_R_OK)
		goto catch;

	strncpy(item->appid, item->pkgid, sizeof(item->pkgid) - 1);
	memset((item->pkgid), 0, MAX_PKG_NAME_LEN);
	strncpy(item->pkgid, pkgid, sizeof(item->pkgid) - 1);

catch:
	pkgmgrinfo_appinfo_destroy_appinfo(handle);

	return ret;
}

static int __process_install(pm_dbus_msg *item)
{
	char *backend_cmd;
	char **argv;
	char args[MAX_PKG_ARGS_LEN] = {'\0', };
	int pid;

	backend_cmd = _get_backend_cmd(item->pkg_type);
	if (backend_cmd == NULL)
		return -1;

	snprintf(args, sizeof(args), "%s -k %s -i %s -u %d %s", backend_cmd,
			item->req_id, item->pkgid, (int)item->uid, item->args);

	argv = __generate_argv(args);

	pid = __fork_and_exec_with_args(argv, item->uid);
	g_strfreev(argv);
	free(backend_cmd);

	return pid;
}

static int __process_mount_install(pm_dbus_msg *item)
{
	char *backend_cmd;
	char **argv;
	char args[MAX_PKG_ARGS_LEN] = {'\0', };
	int pid;

	backend_cmd = _get_backend_cmd(item->pkg_type);
	if (backend_cmd == NULL)
		return -1;

	snprintf(args, sizeof(args), "%s -k %s -w %s %s", backend_cmd,
					 item->req_id, item->pkgid, item->args);

	argv = __generate_argv(args);

	pid = __fork_and_exec_with_args(argv, item->uid);
	g_strfreev(argv);
	free(backend_cmd);

	return pid;
}

static int __process_reinstall(pm_dbus_msg *item)
{
	char *backend_cmd;
	char **argv;
	char args[MAX_PKG_ARGS_LEN];
	int pid;

	backend_cmd = _get_backend_cmd(item->pkg_type);
	if (backend_cmd == NULL)
		return -1;

	snprintf(args, sizeof(args), "%s -k %s -r %s", backend_cmd,
			item->req_id, item->pkgid);
	argv = __generate_argv(args);

	pid = __fork_and_exec_with_args(argv, item->uid);

	g_strfreev(argv);
	free(backend_cmd);

	return pid;
}

static int __process_uninstall(pm_dbus_msg *item)
{
	char *backend_cmd;
	char **argv;
	char args[MAX_PKG_ARGS_LEN];
	int pid;

	backend_cmd = _get_backend_cmd(item->pkg_type);
	if (backend_cmd == NULL)
		return -1;

	snprintf(args, sizeof(args), "%s -k %s -d %s", backend_cmd,
			item->req_id, item->pkgid);
	argv = __generate_argv(args);

	pid = __fork_and_exec_with_args(argv, item->uid);

	g_strfreev(argv);
	free(backend_cmd);

	return pid;
}

static int __process_move(pm_dbus_msg *item)
{
	char *backend_cmd;
	char **argv;
	char args[MAX_PKG_ARGS_LEN];
	int pid;

	backend_cmd = _get_backend_cmd(item->pkg_type);
	if (backend_cmd == NULL)
		return -1;

	snprintf(args, sizeof(args), "%s -k %s -m %s -t %s", backend_cmd,
			item->req_id, item->pkgid, item->args);
	argv = __generate_argv(args);

	pid = __fork_and_exec_with_args(argv, item->uid);

	g_strfreev(argv);
	free(backend_cmd);

	return pid;
}

static int __process_enable_pkg(pm_dbus_msg *item)
{
	/* TODO */
	return 0;
}

static int __process_disable_pkg(pm_dbus_msg *item)
{
	/* TODO */
	return 0;
}

static int __process_enable_app(pm_dbus_msg *item)
{
	int ret = -1;
	bool is_global = false;

	__send_app_signal(item->uid, item->req_id, item->pkgid, item->pkgid,
			PKGMGR_INSTALLER_START_KEY_STR,
			PKGMGR_INSTALLER_APP_ENABLE_EVENT_STR, item->req_type);

	/* get actual pkgid and replace it to appid which is currently stored at pkgid variable */
	ret = __change_item_info(item, item->uid, &is_global);
	if (ret != PMINFO_R_OK || strlen(item->appid) == 0) {
		__send_app_signal(item->uid, item->req_id, item->pkgid, item->pkgid,
				PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_FAIL_EVENT_STR,
				item->req_type);
		return ret;
	}

	ret = pkgmgr_parser_update_app_disable_info_in_usr_db(item->appid, item->uid, 0);
	if (ret != PMINFO_R_OK)
		__send_app_signal(item->uid, item->req_id, item->pkgid, item->appid,
				PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_FAIL_EVENT_STR,
				item->req_type);
	else
		__send_app_signal(item->uid, item->req_id, item->pkgid, item->appid,
				PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_OK_EVENT_STR,
				item->req_type);


	return ret;
}

static int __process_disable_app(pm_dbus_msg *item)
{
	int ret = -1;
	bool is_global = false;

	__send_app_signal(item->uid, item->req_id, item->pkgid, item->pkgid,
			PKGMGR_INSTALLER_START_KEY_STR,
			PKGMGR_INSTALLER_APP_DISABLE_EVENT_STR, item->req_type);

	/* get actual pkgid and replace it to appid which is currently stored at pkgid variable */
	ret = __change_item_info(item, item->uid, &is_global);
	if (ret != PMINFO_R_OK || strlen(item->appid) == 0) {
		__send_app_signal(item->uid, item->req_id, item->pkgid, item->pkgid,
				PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_FAIL_EVENT_STR,
				item->req_type);
		return ret;
	}

	ret = __kill_app(item->appid, item->uid);
	if (ret != PMINFO_R_OK) {
		__send_app_signal(item->uid, item->req_id, item->pkgid, item->appid,
				PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_FAIL_EVENT_STR,
				item->req_type);
	}

	ret = pkgmgr_parser_update_app_disable_info_in_usr_db(item->appid, item->uid, 1);
	if (ret != PMINFO_R_OK)
		__send_app_signal(item->uid, item->req_id, item->pkgid, item->appid,
				PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_FAIL_EVENT_STR,
				item->req_type);
	else
		__send_app_signal(item->uid, item->req_id, item->pkgid, item->appid,
				PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_OK_EVENT_STR,
				item->req_type);

	return ret;
}

static int __process_enable_global_app_for_uid(pm_dbus_msg *item)
{
	int ret = -1;
	bool is_global = true;

	__send_app_signal(item->uid, item->req_id, item->pkgid, item->pkgid,
			PKGMGR_INSTALLER_START_KEY_STR,
			PKGMGR_INSTALLER_GLOBAL_APP_ENABLE_FOR_UID, item->req_type);

	/* get actual pkgid and replace it to appid which is currently stored at pkgid variable */
	ret = __change_item_info(item, item->uid, &is_global);
	if (ret != PMINFO_R_OK || strlen(item->appid) == 0) {
		__send_app_signal(item->uid, item->req_id, item->pkgid, item->pkgid,
				PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_FAIL_EVENT_STR,
				item->req_type);
		return ret;
	}

	ret = pkgmgr_parser_update_global_app_disable_for_uid_info_in_db(item->appid, item->uid, 0);
	if (ret != PMINFO_R_OK)
		__send_app_signal(item->uid, item->req_id, item->pkgid, item->appid,
				PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_FAIL_EVENT_STR,
				item->req_type);
	else
		__send_app_signal(item->uid, item->req_id, item->pkgid, item->appid,
				PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_OK_EVENT_STR,
				item->req_type);

	return ret;
}

static int __process_disable_global_app_for_uid(pm_dbus_msg *item)
{
	int ret = -1;
	bool is_global = true;

	__send_app_signal(item->uid, item->req_id,
			item->pkgid, item->pkgid,
			PKGMGR_INSTALLER_START_KEY_STR,
			PKGMGR_INSTALLER_GLOBAL_APP_DISABLE_FOR_UID, item->req_type);

	/* get actual pkgid and replace it to appid which is currently stored at pkgid variable */
	ret = __change_item_info(item, GLOBAL_USER, &is_global);
	if (ret != PMINFO_R_OK || strlen(item->appid) == 0) {
		__send_app_signal(item->uid, item->req_id, item->pkgid, item->pkgid,
				PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_FAIL_EVENT_STR,
				item->req_type);
		return ret;
	}

	ret = __kill_app(item->appid, item->uid);
	ret = pkgmgr_parser_update_global_app_disable_for_uid_info_in_db(item->appid,
		item->uid, 1);

	if (ret != PMINFO_R_OK)
		__send_app_signal(item->uid, item->req_id, item->pkgid, item->appid,
				PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_FAIL_EVENT_STR,
				item->req_type);
	else
		__send_app_signal(item->uid, item->req_id, item->pkgid, item->appid,
				PKGMGR_INSTALLER_END_KEY_STR, PKGMGR_INSTALLER_OK_EVENT_STR,
				item->req_type);

	return ret;
}

static int __process_getsize(pm_dbus_msg *item)
{
	static const char *backend_cmd = "/usr/bin/pkg_getsize";
	char **argv;
	char args[MAX_PKG_ARGS_LEN];
	int pid;

	snprintf(args, sizeof(args), "%s %s %s -k %s", backend_cmd, item->pkgid,
			item->args, item->req_id);
	argv = __generate_argv(args);
	pid = __fork_and_exec_with_args(argv, item->uid);

	g_strfreev(argv);

	return pid;
}

static int __process_cleardata(pm_dbus_msg *item)
{
	char *backend_cmd;
	char **argv;
	char args[MAX_PKG_ARGS_LEN];
	int pid;

	backend_cmd = _get_backend_cmd(item->pkg_type);
	if (backend_cmd == NULL)
		return -1;

	/* TODO: set movetype */
	snprintf(args, sizeof(args), "%s -k %s -c %s", backend_cmd,
			item->req_id, item->pkgid);
	argv = __generate_argv(args);

	pid = __fork_and_exec_with_args(argv, item->uid);

	g_strfreev(argv);
	free(backend_cmd);

	return pid;
}

static int __process_clearcache(pm_dbus_msg *item)
{
	static const char *backend_cmd = "/usr/bin/pkg_clearcache";
	char **argv;
	char args[MAX_PKG_ARGS_LEN];
	int pid;

	snprintf(args, sizeof(args), "%s %s", backend_cmd, item->pkgid);
	argv = __generate_argv(args);
	pid = __fork_and_exec_with_args(argv, item->uid);

	g_strfreev(argv);

	return pid;
}

static int __process_kill(pm_dbus_msg *item)
{
	int ret;
	pkgmgrinfo_pkginfo_h handle;
	pkgcmd_data *pdata = NULL;

	ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(item->pkgid, item->uid,
			&handle);
	if (ret < 0) {
		ERR("Failed to get handle");
		return -1;
	}

	pdata = calloc(1, sizeof(pkgcmd_data));
	if (pdata == NULL) {
		ERR("memory alloc failed");
		return -1;
	}
	pdata->cmd = strdup("kill");
	if (pdata->cmd == NULL) {
		ERR("out of memory");
		free(pdata);
		pdata = NULL;
		return -1;
	}
	pdata->uid = item->uid;
	ret = pkgmgrinfo_appinfo_get_usr_list(handle, PMINFO_ALL_APP,
			__pkgcmd_app_cb, pdata, item->uid);
	free(pdata->cmd);
	free(pdata);
	pdata = NULL;
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	if (ret < 0) {
		ERR("pkgmgrinfo_appinfo_get_list() failed");
		return -1;
	}

	return 0;
}

static int __process_check(pm_dbus_msg *item)
{
	int ret;
	pkgmgrinfo_pkginfo_h handle;
	pkgcmd_data *pdata = NULL;

	ret = pkgmgrinfo_pkginfo_get_usr_pkginfo(item->pkgid, item->uid,
			&handle);
	if (ret < 0) {
		ERR("Failed to get handle");
		return -1;
	}

	pdata = calloc(1, sizeof(pkgcmd_data));
	if (pdata == NULL) {
		ERR("memory alloc failed");
		return -1;
	}
	pdata->cmd = strdup("check");
	if (pdata->cmd == NULL) {
		ERR("out of memory");
		free(pdata);
		pdata = NULL;
		return -1;
	}
	pdata->uid = item->uid;
	ret = pkgmgrinfo_appinfo_get_usr_list(handle, PMINFO_ALL_APP,
			__pkgcmd_app_cb, pdata, item->uid);
	free(pdata->cmd);
	free(pdata);
	pdata = NULL;
	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
	if (ret < 0) {
		ERR("pkgmgrinfo_appinfo_get_list() failed");
		return -1;
	}

	return 0;
}

static int __process_generate_license_request(pm_dbus_msg *item)
{
	int ret;
	char *resp_data;
	char req_data[MAX_PKG_ARGS_LEN];
	unsigned int req_data_len;
	char license_url[MAX_PKG_ARGS_LEN];
	unsigned int license_url_len;

	resp_data = item->args;
	req_data_len = sizeof(req_data);
	license_url_len = sizeof(license_url);

	ret = drm_tizen_generate_license_request(resp_data, strlen(resp_data),
			req_data, &req_data_len, license_url, &license_url_len);
	if (ret != TADC_SUCCESS) {
		ERR("drm_tizen_generate_license_request failed: %d", ret);
		__return_value_to_caller(item->req_id, g_variant_new("(iss)",
					PKGMGR_R_ESYSTEM, "", ""));
		return -1;
	}

	__return_value_to_caller(item->req_id,
			g_variant_new("(iss)", PKGMGR_R_OK, req_data,
				license_url));

	return 0;
}

static int __process_register_license(pm_dbus_msg *item)
{
	int ret;
	char *resp_data;

	resp_data = item->args;

	ret = drm_tizen_register_license(resp_data, strlen(resp_data));
	if (ret != TADC_SUCCESS) {
		ERR("drm_tizen_register_license failed: %d", ret);
		__return_value_to_caller(item->req_id,
				g_variant_new("(i)", PKGMGR_R_ESYSTEM));
		return -1;
	}

	__return_value_to_caller(item->req_id,
			g_variant_new("(i)", PKGMGR_R_OK));

	return 0;
}

static int __process_decrypt_package(pm_dbus_msg *item)
{
	int ret;
	char *drm_file_path;
	char *decrypted_file_path;

	drm_file_path = item->pkgid;
	decrypted_file_path = item->args;

	/* TODO: check ownership of decrypted file */
	ret = drm_tizen_decrypt_package(drm_file_path, strlen(drm_file_path),
			decrypted_file_path, strlen(decrypted_file_path));
	if (ret != TADC_SUCCESS) {
		ERR("drm_tizen_register_license failed: %d", ret);
		__return_value_to_caller(item->req_id,
				g_variant_new("(i)", PKGMGR_R_ESYSTEM));
		return -1;
	}

	__return_value_to_caller(item->req_id,
			g_variant_new("(i)", PKGMGR_R_OK));

	return 0;
}

static int __process_update_app_splash_screen(pm_dbus_msg *item, int flag)
{
	int ret;
	bool is_global = false;
	const char *val;

	ret = __change_item_info(item, item->uid, &is_global);
	if (ret != PMINFO_R_OK || strlen(item->appid) == 0)
		return -1;

	val = flag ? PKGMGR_INSTALLER_APP_ENABLE_SPLASH_SCREEN_EVENT_STR :
		PKGMGR_INSTALLER_APP_DISABLE_SPLASH_SCREEN_EVENT_STR;
	__send_app_signal(item->uid, item->req_id, item->pkgid, item->appid,
			PKGMGR_INSTALLER_START_KEY_STR, val, item->req_type);

	if (is_global)
		ret = pkgmgr_parser_update_global_app_splash_screen_display_info_in_usr_db(
				item->appid, item->uid, flag);
	else
		ret = pkgmgr_parser_update_app_splash_screen_display_info_in_usr_db(
			item->appid, item->uid, flag);
	if (ret != PMINFO_R_OK)
		__send_app_signal(item->uid, item->req_id, item->pkgid,
				item->appid, PKGMGR_INSTALLER_END_KEY_STR,
				PKGMGR_INSTALLER_FAIL_EVENT_STR,
				item->req_type);
	else
		__send_app_signal(item->uid, item->req_id, item->pkgid,
				item->appid, PKGMGR_INSTALLER_END_KEY_STR,
				PKGMGR_INSTALLER_OK_EVENT_STR,
				item->req_type);

	return ret;
}

static int __process_set_restriction_mode(pm_dbus_msg *item)
{
	int ret;
	int mode;

	mode = atoi(item->args);
	ret = _restriction_mode_set(item->uid, item->pkgid, mode);

	__return_value_to_caller(item->req_id,
			g_variant_new("(i)", ret));

	return ret;
}

static int __process_unset_restriction_mode(pm_dbus_msg *item)
{
	int ret;
	int mode;

	mode = atoi(item->args);
	ret = _restriction_mode_unset(item->uid, item->pkgid, mode);

	__return_value_to_caller(item->req_id,
			g_variant_new("(i)", ret));

	return ret;
}

static int __process_get_restriction_mode(pm_dbus_msg *item)
{
	int ret;
	int mode = -1;

	ret = _restriction_mode_get(item->uid, item->pkgid, &mode);

	__return_value_to_caller(item->req_id,
			g_variant_new("(ii)", mode, ret));

	return ret;
}

gboolean queue_job(void *data)
{
	pm_dbus_msg *item = NULL;
	backend_info *ptr;
	int x;
	int ret;

	/* Pop a job from queue */
	for (x = 0, ptr = begin; x < num_of_backends; x++, ptr++) {
		if (__is_backend_busy(x))
			continue;

		item = _pm_queue_pop(x);
		if (item && item->req_type != -1)
			break;
		free(item);
	}

	/* all backend messages queue are empty or busy */
	if (x == num_of_backends)
		return FALSE;

	/*save pkg type and pkg name for future*/
	strncpy(ptr->req_id, item->req_id, MAX_REQ_ID_LEN - 1);
	strncpy(ptr->pkgtype, item->pkg_type, MAX_PKG_TYPE_LEN - 1);
	strncpy(ptr->pkgid, item->pkgid, MAX_PKG_NAME_LEN - 1);
	strncpy(ptr->args, item->args, MAX_PKG_ARGS_LEN - 1);
	memset((item->appid), 0, MAX_PKG_NAME_LEN);
	ptr->uid = item->uid;
	ptr->req_type = item->req_type;
	DBG("handle request type [%d]", item->req_type);

	switch (item->req_type) {
	case PKGMGR_REQUEST_TYPE_INSTALL:
		__set_backend_busy(x);
		ret = __process_install(item);
		break;
	case PKGMGR_REQUEST_TYPE_MOUNT_INSTALL:
		__set_backend_busy(x);
		ret = __process_mount_install(item);
		break;
	case PKGMGR_REQUEST_TYPE_REINSTALL:
		__set_backend_busy(x);
		ret = __process_reinstall(item);
		break;
	case PKGMGR_REQUEST_TYPE_UNINSTALL:
		__set_backend_busy(x);
		ret = __process_uninstall(item);
		break;
	case PKGMGR_REQUEST_TYPE_MOVE:
		__set_backend_busy(x);
		ret = __process_move(item);
		break;
	case PKGMGR_REQUEST_TYPE_ENABLE_PKG:
		ret = __process_enable_pkg(item);
		break;
	case PKGMGR_REQUEST_TYPE_DISABLE_PKG:
		ret = __process_disable_pkg(item);
		break;
	case PKGMGR_REQUEST_TYPE_ENABLE_APP:
		ret = __process_enable_app(item);
		break;
	case PKGMGR_REQUEST_TYPE_DISABLE_APP:
		ret = __process_disable_app(item);
		break;
	case PKGMGR_REQUEST_TYPE_GETSIZE:
		__set_backend_busy(x);
		ret = __process_getsize(item);
		break;
	case PKGMGR_REQUEST_TYPE_CLEARDATA:
		__set_backend_busy(x);
		ret = __process_cleardata(item);
		break;
	case PKGMGR_REQUEST_TYPE_CLEARCACHE:
		__set_backend_busy(x);
		ret = __process_clearcache(item);
		break;
	case PKGMGR_REQUEST_TYPE_ENABLE_GLOBAL_APP_FOR_UID:
		ret = __process_enable_global_app_for_uid(item);
		break;
	case PKGMGR_REQUEST_TYPE_DISABLE_GLOBAL_APP_FOR_UID:
		ret = __process_disable_global_app_for_uid(item);
		break;
	case PKGMGR_REQUEST_TYPE_KILL:
		ret = __process_kill(item);
		break;
	case PKGMGR_REQUEST_TYPE_CHECK:
		ret = __process_check(item);
		break;
	case PKGMGR_REQUEST_TYPE_GENERATE_LICENSE_REQUEST:
		ret = __process_generate_license_request(item);
		break;
	case PKGMGR_REQUEST_TYPE_REGISTER_LICENSE:
		ret = __process_register_license(item);
		break;
	case PKGMGR_REQUEST_TYPE_DECRYPT_PACKAGE:
		ret = __process_decrypt_package(item);
		break;
	case PKGMGR_REQUEST_TYPE_ENABLE_APP_SPLASH_SCREEN:
		ret = __process_update_app_splash_screen(item, 1);
		break;
	case PKGMGR_REQUEST_TYPE_DISABLE_APP_SPLASH_SCREEN:
		ret = __process_update_app_splash_screen(item, 0);
		break;
	case PKGMGR_REQUEST_TYPE_SET_RESTRICTION_MODE:
		ret = __process_set_restriction_mode(item);
		break;
	case PKGMGR_REQUEST_TYPE_UNSET_RESTRICTION_MODE:
		ret = __process_unset_restriction_mode(item);
		break;
	case PKGMGR_REQUEST_TYPE_GET_RESTRICTION_MODE:
		ret = __process_get_restriction_mode(item);
		break;
	default:
		ret = -1;
		break;
	}

	ptr->pid = ret;
	free(item);

	return FALSE;
}

#define IS_WHITESPACE(CHAR) \
((CHAR == ' ' || CHAR == '\t' || CHAR == '\r' || CHAR == '\n') ? TRUE : FALSE)

void _app_str_trim(char *input)
{
	char *trim_str = input;

	if (input == NULL)
		return;

	while (*input != 0) {
		if (!IS_WHITESPACE(*input)) {
			*trim_str = *input;
			trim_str++;
		}
		input++;
	}

	*trim_str = 0;
	return;
}

char *_get_backend_cmd(char *type)
{
	FILE *fp = NULL;
	char buffer[1024] = { 0 };
	char *command = NULL;
	int size = 0;
	fp = fopen(PKG_CONF_PATH, "r");
	if (fp == NULL) {
		return NULL;
	}

	char *path = NULL;
	while (fgets(buffer, 1024, fp) != NULL) {
		if (buffer[0] == '#')
			continue;

		_app_str_trim(buffer);

		if ((path = strstr(buffer, PKG_BACKEND)) != NULL) {
			DBG("buffer [%s]", buffer);
			path = path + strlen(PKG_BACKEND);
			DBG("path [%s]", path);

			command =
			    (char *)malloc(sizeof(char) * strlen(path) +
					   strlen(type) + 1);
			if (command == NULL) {
				fclose(fp);
				return NULL;
			}

			size = strlen(path) + strlen(type) + 1;
			snprintf(command, size, "%s%s", path, type);
			command[strlen(path) + strlen(type)] = '\0';
			DBG("command [%s]", command);

			if (fp != NULL)
				fclose(fp);

			return command;
		}

		memset(buffer, 0x00, 1024);
	}

	if (fp != NULL)
		fclose(fp);

	return NULL;		/* cannot find proper command */
}

int main(int argc, char *argv[])
{
	int r;

	DBG("server start");

	r = _pm_queue_init();
	if (r) {
		DBG("Queue Initialization Failed\n");
		return -1;
	}

	r = __init_backend_info();
	if (r) {
		DBG("backend info init failed");
		return -1;
	}

	r = __init_request_handler();
	if (r) {
		ERR("dbus init failed");
		return -1;
	}

	if (__register_signal_handler()) {
		ERR("failed to register signal handler");
		return -1;
	}

#if !GLIB_CHECK_VERSION(2,35,0)
	g_type_init();
#endif
	mainloop = g_main_loop_new(NULL, FALSE);
	if (!mainloop) {
		ERR("g_main_loop_new failed");
		return -1;
	}

	DBG("Main loop is created.");

	g_main_loop_run(mainloop);

	DBG("Quit main loop.");
	__fini_request_handler();
	__fini_backend_info();
	_pm_queue_final();

	DBG("package manager server terminated.");

	return 0;
}
