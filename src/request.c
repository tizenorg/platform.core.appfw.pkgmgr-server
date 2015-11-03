#include <sys/types.h>
#include <sys/time.h>

#include <glib.h>
#include <gio/gio.h>

#include "comm_config.h"
#include "pm-queue.h"
#include "pkgmgr-server.h"
#include "package-manager.h"
#include "package-manager-debug.h"

static const char instropection_xml[] =
	"<node>"
	"  <interface name='org.tizen.pkgmgr'>"
	"    <method name='install'>"
	"      <arg type='u' name='uid' direction='in'/>"
	"      <arg type='s' name='pkgtype' direction='in'/>"
	"      <arg type='s' name='pkgpath' direction='in'/>"
	"      <arg type='s' name='args' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"      <arg type='s' name='reqkey' direction='out'/>"
	"    </method>"
	"    <method name='reinstall'>"
	"      <arg type='u' name='uid' direction='in'/>"
	"      <arg type='s' name='pkgtype' direction='in'/>"
	"      <arg type='s' name='pkgid' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"      <arg type='s' name='reqkey' direction='out'/>"
	"    </method>"
	"    <method name='uninstall'>"
	"      <arg type='u' name='uid' direction='in'/>"
	"      <arg type='s' name='pkgtype' direction='in'/>"
	"      <arg type='s' name='pkgid' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"      <arg type='s' name='reqkey' direction='out'/>"
	"    </method>"
	"    <method name='move'>"
	"      <arg type='u' name='uid' direction='in'/>"
	"      <arg type='s' name='pkgtype' direction='in'/>"
	"      <arg type='s' name='pkgid' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"      <arg type='s' name='reqkey' direction='out'/>"
	"    </method>"
	"    <method name='enable_pkg'>"
	"      <arg type='u' name='uid' direction='in'/>"
	"      <arg type='s' name='pkgid' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"    </method>"
	"    <method name='disable_pkg'>"
	"      <arg type='u' name='uid' direction='in'/>"
	"      <arg type='s' name='pkgid' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"    </method>"
	"    <method name='enable_app'>"
	"      <arg type='u' name='uid' direction='in'/>"
	"      <arg type='s' name='appid' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"    </method>"
	"    <method name='disable_app'>"
	"      <arg type='u' name='uid' direction='in'/>"
	"      <arg type='s' name='appid' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"    </method>"
	"    <method name='getsize'>"
	"      <arg type='u' name='uid' direction='in'/>"
	"      <arg type='s' name='pkgid' direction='in'/>"
	"      <arg type='i' name='get_type' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"      <arg type='s' name='reqkey' direction='out'/>"
	"    </method>"
	"    <method name='cleardata'>"
	"      <arg type='u' name='uid' direction='in'/>"
	"      <arg type='s' name='pkgtype' direction='in'/>"
	"      <arg type='s' name='pkgid' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"    </method>"
	"    <method name='clearcache'>"
	"      <arg type='u' name='uid' direction='in'/>"
	"      <arg type='s' name='pkgid' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"    </method>"
	"    <method name='kill'>"
	"      <arg type='u' name='uid' direction='in'/>"
	"      <arg type='s' name='pkgid' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"    </method>"
	"    <method name='check'>"
	"      <arg type='u' name='uid' direction='in'/>"
	"      <arg type='s' name='pkgid' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"    </method>"
	"  </interface>"
	"</node>";
static GDBusNodeInfo *instropection_data;
static guint reg_id;
static guint owner_id;

static char *__generate_reqkey(const char *pkgid)
{
	struct timeval tv;
	long curtime;
	char timestr[MAX_PKG_ARGS_LEN];
	char *str_req_key;
	int size;

	gettimeofday(&tv, NULL);
	curtime = tv.tv_sec * 1000000 + tv.tv_usec;
	snprintf(timestr, sizeof(timestr), "%ld", curtime);

	size = strlen(pkgid) + strlen(timestr) + 2;
	str_req_key = (char *)calloc(size, sizeof(char));
	if (str_req_key == NULL) {
		DBG("calloc failed");
		return NULL;
	}
	snprintf(str_req_key, size, "%s_%s", pkgid, timestr);

	return str_req_key;
}

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
char *__get_tep_path_from_args(char *args)
{
	if (args == NULL)
		return NULL;

	gboolean ret_parse;
	gint argcp;
	gchar **argvp;
	GError *gerr = NULL;
	int i = 0;
	char *tep_path = NULL;

	ret_parse = g_shell_parse_argv(args, &argcp, &argvp, &gerr);
	if (ret_parse == false) {
		ERR("failed to parse args [%s]", args);
		return NULL;
	}

	for(i = 0; i < argcp; i++) {
		if (strcmp(argvp[i], "-e") == 0) {
			if (argvp[++i] != NULL) {
				tep_path = strdup(argvp[i]);
				return tep_path;
			} else
				return NULL;
		}
	}

	return NULL;
}
#endif

static int __handle_request_install(uid_t uid,
		GDBusMethodInvocation *invocation, GVariant *parameters)
{
	uid_t target_uid = (uid_t)-1;
	char *pkgtype = NULL;
	char *pkgpath = NULL;
	char *args = NULL;
	char *reqkey;
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	char *tep_path = NULL;
#endif

	g_variant_get(parameters, "(u&s&s&s)", &target_uid, &pkgtype, &pkgpath, &args);
	if (target_uid == (uid_t)-1 || pkgtype == NULL) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(is)", PKGMGR_R_ECOMM, ""));
		return -1;
	}

	if (pkgpath == NULL) {
#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
		tep_path = __get_tep_path_from_args(args);
		if (tep_path == NULL) {
			g_dbus_method_invocation_return_value(invocation,
					g_variant_new("(is)", PKGMGR_R_ECOMM, ""));
			return -1;
		}
#else
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(is)", PKGMGR_R_ECOMM, ""));
		return -1;
#endif
	}

#ifdef _APPFW_FEATURE_EXPANSION_PKG_INSTALL
	if (pkgpath)
		reqkey = __generate_reqkey(pkgpath);
	else
		reqkey = __generate_reqkey(tep_path);

	if (tep_path)
		free(tep_path);
#else
	reqkey = __generate_reqkey(pkgpath);
#endif

	if (reqkey == NULL)
		return -1;
	if (_pm_queue_push(target_uid, reqkey, PKGMGR_REQUEST_TYPE_INSTALL, pkgtype,
				pkgpath, args)) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(is)", PKGMGR_R_ESYSTEM, ""));
		free(reqkey);
		return -1;
	}

	g_dbus_method_invocation_return_value(invocation,
			g_variant_new("(is)", PKGMGR_R_OK, reqkey));
	free(reqkey);

	return 0;
}

static int __handle_request_reinstall(uid_t uid,
		GDBusMethodInvocation *invocation, GVariant *parameters)
{
	uid_t target_uid = (uid_t)-1;
	char *pkgtype = NULL;
	char *pkgid = NULL;
	char *reqkey;

	g_variant_get(parameters, "(u&s&s)", &target_uid, &pkgtype, &pkgid);
	if (target_uid == (uid_t)-1 || pkgtype == NULL || pkgid == NULL) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(is)", PKGMGR_R_ECOMM, ""));
		return -1;
	}

	reqkey = __generate_reqkey(pkgid);
	if (reqkey == NULL)
		return -1;
	if (_pm_queue_push(target_uid, reqkey, PKGMGR_REQUEST_TYPE_REINSTALL, pkgtype,
				pkgid, "")) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(is)", PKGMGR_R_ESYSTEM, ""));
		free(reqkey);
		return -1;
	}

	g_dbus_method_invocation_return_value(invocation,
			g_variant_new("(is)", PKGMGR_R_OK, reqkey));
	free(reqkey);

	return 0;
}

static int __handle_request_uninstall(uid_t uid,
		GDBusMethodInvocation *invocation, GVariant *parameters)
{
	uid_t target_uid = (uid_t)-1;
	char *pkgtype = NULL;
	char *pkgid = NULL;
	char *reqkey;

	g_variant_get(parameters, "(u&s&s)", &target_uid, &pkgtype, &pkgid);
	if (target_uid == (uid_t)-1 || pkgtype == NULL || pkgid == NULL) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(is)", PKGMGR_R_ECOMM, ""));
		return -1;
	}

	reqkey = __generate_reqkey(pkgid);
	if (reqkey == NULL)
		return -1;
	if (_pm_queue_push(target_uid, reqkey, PKGMGR_REQUEST_TYPE_UNINSTALL, pkgtype,
				pkgid, "")) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(is)", PKGMGR_R_ESYSTEM, ""));
		free(reqkey);
		return -1;
	}

	g_dbus_method_invocation_return_value(invocation,
			g_variant_new("(is)", PKGMGR_R_OK, reqkey));
	free(reqkey);

	return 0;
}

static int __handle_request_move(uid_t uid,
		GDBusMethodInvocation *invocation, GVariant *parameters)
{
	uid_t target_uid = (uid_t)-1;
	char *pkgtype = NULL;
	char *pkgid = NULL;
	char *reqkey;

	g_variant_get(parameters, "(u&s&s)", &target_uid, &pkgtype, &pkgid);
	if (target_uid == (uid_t)-1 || pkgtype == NULL || pkgid == NULL) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(is)", PKGMGR_R_ECOMM, ""));
		return -1;
	}

	reqkey = __generate_reqkey(pkgid);
	if (reqkey == NULL)
		return -1;
	if (_pm_queue_push(target_uid, reqkey, PKGMGR_REQUEST_TYPE_MOVE, pkgtype,
				pkgid, "")) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(is)", PKGMGR_R_ESYSTEM, ""));
		free(reqkey);
		return -1;
	}

	g_dbus_method_invocation_return_value(invocation,
			g_variant_new("(is)", PKGMGR_R_OK, reqkey));
	free(reqkey);

	return 0;
}

static int __handle_request_enable(uid_t uid,
		GDBusMethodInvocation *invocation, GVariant *parameters)
{
	uid_t target_uid = (uid_t)-1;
	char *pkgid = NULL;

	g_variant_get(parameters, "(u&s)", &target_uid, &pkgid);
	if (target_uid == (uid_t)-1 || pkgid == NULL) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(i)", PKGMGR_R_ECOMM));
		return -1;
	}

	if (_pm_queue_push(target_uid, "", PKGMGR_REQUEST_TYPE_ENABLE, "pkg",
				pkgid, "")) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(i)", PKGMGR_R_ESYSTEM));
		return -1;
	}

	g_dbus_method_invocation_return_value(invocation,
			g_variant_new("(i)", PKGMGR_R_OK));

	return 0;
}

static int __handle_request_disable(uid_t uid,
		GDBusMethodInvocation *invocation, GVariant *parameters)
{
	uid_t target_uid = (uid_t)-1;
	char *pkgid = NULL;

	g_variant_get(parameters, "(u&s)", &target_uid, &pkgid);
	if (target_uid == (uid_t)-1 || pkgid == NULL) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(i)", PKGMGR_R_ECOMM));
		return -1;
	}

	if (_pm_queue_push(target_uid, "", PKGMGR_REQUEST_TYPE_DISABLE, "pkg",
				pkgid, "")) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(i)", PKGMGR_R_ESYSTEM));
		return -1;
	}

	g_dbus_method_invocation_return_value(invocation,
			g_variant_new("(i)", PKGMGR_R_OK));

	return 0;
}

static int __handle_request_getsize(uid_t uid,
		GDBusMethodInvocation *invocation, GVariant *parameters)
{
	uid_t target_uid = (uid_t)-1;
	char *pkgid = NULL;
	int get_type = -1;
	char *reqkey;
	char buf[4];

	g_variant_get(parameters, "(u&si)", &target_uid, &pkgid, &get_type);
	if (target_uid == (uid_t)-1 || pkgid == NULL || get_type == -1) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(is)", PKGMGR_R_ECOMM, ""));
		return -1;
	}

	reqkey = __generate_reqkey(pkgid);
	if (reqkey == NULL)
		return -1;

	snprintf(buf, sizeof(buf), "%d", get_type);
	if (_pm_queue_push(target_uid, reqkey, PKGMGR_REQUEST_TYPE_GETSIZE, "getsize",
				pkgid, buf)) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(is)", PKGMGR_R_ESYSTEM, ""));
		free(reqkey);
		return -1;
	}

	g_dbus_method_invocation_return_value(invocation,
			g_variant_new("(is)", PKGMGR_R_OK, reqkey));
	free(reqkey);

	return 0;
}

static int __handle_request_cleardata(uid_t uid,
		GDBusMethodInvocation *invocation, GVariant *parameters)
{
	uid_t target_uid = (uid_t)-1;
	char *pkgtype = NULL;
	char *pkgid = NULL;

	g_variant_get(parameters, "(u&s&s)", &target_uid, &pkgtype, &pkgid);
	if (target_uid == (uid_t)-1 || pkgtype == NULL || pkgid == NULL) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(i)", PKGMGR_R_ECOMM));
		return -1;
	}

	if (_pm_queue_push(target_uid, "", PKGMGR_REQUEST_TYPE_CLEARDATA, pkgtype,
				pkgid, "")) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(i)", PKGMGR_R_ESYSTEM));
		return -1;
	}

	g_dbus_method_invocation_return_value(invocation,
			g_variant_new("(i)", PKGMGR_R_OK));

	return 0;
}

static int __handle_request_clearcache(uid_t uid,
		GDBusMethodInvocation *invocation, GVariant *parameters)
{
	uid_t target_uid = (uid_t)-1;
	char *pkgid = NULL;

	g_variant_get(parameters, "(u&s)", &target_uid, &pkgid);
	if (target_uid == (uid_t)-1 || pkgid == NULL) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(i)", PKGMGR_R_ECOMM));
		return -1;
	}

	if (_pm_queue_push(target_uid, "", PKGMGR_REQUEST_TYPE_CLEARCACHE,
				"clearcache", pkgid, "")) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(i)", PKGMGR_R_ESYSTEM));
		return -1;
	}

	g_dbus_method_invocation_return_value(invocation,
			g_variant_new("(i)", PKGMGR_R_OK));

	return 0;
}

static int __handle_request_kill(uid_t uid,
		GDBusMethodInvocation *invocation, GVariant *parameters)
{
	uid_t target_uid = (uid_t)-1;
	char *pkgid = NULL;

	g_variant_get(parameters, "(u&s)", &target_uid, &pkgid);
	if (target_uid == (uid_t)-1 || pkgid == NULL) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(i)", PKGMGR_R_ECOMM));
		return -1;
	}

	if (_pm_queue_push(target_uid, "", PKGMGR_REQUEST_TYPE_KILL, "pkg",
				pkgid, "")) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(i)", PKGMGR_R_ESYSTEM));
		return -1;
	}

	g_dbus_method_invocation_return_value(invocation,
			g_variant_new("(i)", PKGMGR_R_OK));

	return 0;
}

static int __handle_request_check(uid_t uid,
		GDBusMethodInvocation *invocation, GVariant *parameters)
{
	uid_t target_uid = (uid_t)-1;
	char *pkgid = NULL;

	g_variant_get(parameters, "(u&s)", &target_uid, &pkgid);
	if (target_uid == (uid_t)-1 || pkgid == NULL) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(i)", PKGMGR_R_ECOMM));
		return -1;
	}

	if (_pm_queue_push(target_uid, "", PKGMGR_REQUEST_TYPE_CHECK, "pkg",
				pkgid, "")) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(i)", PKGMGR_R_ESYSTEM));
		return -1;
	}

	g_dbus_method_invocation_return_value(invocation,
			g_variant_new("(i)", PKGMGR_R_OK));

	return 0;
}

static uid_t __get_caller_uid(GDBusConnection *connection, const char *name)
{
	GError *err = NULL;
	GVariant *result;
	uid_t uid;

	result = g_dbus_connection_call_sync(connection,
			"org.freedesktop.DBus", "/org/freedesktop/DBus",
			"org.freedesktop.DBus", "GetConnectionUnixUser",
			g_variant_new("(s)", name), NULL,
			G_DBUS_CALL_FLAGS_NONE, -1, NULL, &err);
	if (result == NULL) {
		ERR("failed to get caller uid: %s", err->message);
		g_error_free(err);
		return (uid_t)-1;
	}

	g_variant_get(result, "(u)", &uid);

	return uid;
}

static void __handle_method_call(GDBusConnection *connection,
		const gchar *sender, const gchar *object_path,
		const gchar *interface_name, const gchar *method_name,
		GVariant *parameters, GDBusMethodInvocation *invocation,
		gpointer user_data)
{
	int ret;
	uid_t uid;

	uid = __get_caller_uid(connection,
		g_dbus_method_invocation_get_sender(invocation));
	if (uid == (uid_t)-1)
		return;

	if (g_strcmp0(method_name, "install") == 0)
		ret = __handle_request_install(uid, invocation, parameters);
	else if (g_strcmp0(method_name, "reinstall") == 0)
		ret = __handle_request_reinstall(uid, invocation, parameters);
	else if (g_strcmp0(method_name, "uninstall") == 0)
		ret = __handle_request_uninstall(uid, invocation, parameters);
	else if (g_strcmp0(method_name, "cleardata") == 0)
		ret = __handle_request_cleardata(uid, invocation, parameters);
	else if (g_strcmp0(method_name, "move") == 0)
		ret = __handle_request_move(uid, invocation, parameters);
	else if (g_strcmp0(method_name, "enable") == 0)
		ret = __handle_request_enable(uid, invocation, parameters);
	else if (g_strcmp0(method_name, "disable") == 0)
		ret = __handle_request_disable(uid, invocation, parameters);
	else if (g_strcmp0(method_name, "getsize") == 0)
		ret = __handle_request_getsize(uid, invocation, parameters);
	else if (g_strcmp0(method_name, "clearcache") == 0)
		ret = __handle_request_clearcache(uid, invocation, parameters);
	else if (g_strcmp0(method_name, "kill") == 0)
		ret = __handle_request_kill(uid, invocation, parameters);
	else if (g_strcmp0(method_name, "check") == 0)
		ret = __handle_request_check(uid, invocation, parameters);
	else
		ret = -1;

	if (ret == 0)
		g_idle_add(queue_job, NULL);
}

static const GDBusInterfaceVTable interface_vtable =
{
	__handle_method_call,
	NULL,
	NULL,
};

static void __on_bus_acquired(GDBusConnection *connection, const gchar *name,
		gpointer user_data)
{
	GError *err = NULL;

	DBG("on bus acquired");

	reg_id = g_dbus_connection_register_object(connection,
			COMM_PKGMGR_DBUS_OBJECT_PATH,
			instropection_data->interfaces[0],
			&interface_vtable, NULL, NULL, &err);

	if (reg_id == 0) {
		ERR("failed to register object: %s", err->message);
		g_error_free(err);
	}
}

static void __on_name_acquired(GDBusConnection *connection, const gchar *name,
		gpointer user_data)
{
	DBG("on name acquired: %s", name);
}

static void __on_name_lost(GDBusConnection *connection, const gchar *name,
		gpointer user_data)
{
	DBG("on name lost: %s", name);
}

int __init_request_handler(void)
{
	instropection_data = g_dbus_node_info_new_for_xml(instropection_xml, NULL);

	owner_id = g_bus_own_name(G_BUS_TYPE_SYSTEM, COMM_PKGMGR_DBUS_SERVICE,
			G_BUS_NAME_OWNER_FLAGS_NONE, __on_bus_acquired,
			__on_name_acquired, __on_name_lost, NULL, NULL);

	return 0;
}

void __fini_request_handler(void)
{
	g_bus_unown_name(owner_id);
	g_dbus_node_info_unref(instropection_data);
}
