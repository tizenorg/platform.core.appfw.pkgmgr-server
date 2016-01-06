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
	"      <arg type='as' name='args' direction='in'/>"
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
	"    <method name='generate_license_request'>"
	"      <arg type='s' name='resp_data' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"      <arg type='s' name='req_data' direction='out'/>"
	"      <arg type='s' name='license_url' direction='out'/>"
	"    </method>"
	"    <method name='register_license'>"
	"      <arg type='s' name='resp_data' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"    </method>"
	"    <method name='decrypt_package'>"
	"      <arg type='s' name='drm_file_path' direction='in'/>"
	"      <arg type='s' name='decrypted_file_path' direction='in'/>"
	"      <arg type='i' name='ret' direction='out'/>"
	"    </method>"
	"  </interface>"
	"</node>";
static GDBusNodeInfo *instropection_data;
static guint reg_id;
static guint owner_id;
static GHashTable *req_table;

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

static int __handle_request_install(uid_t uid,
		GDBusMethodInvocation *invocation, GVariant *parameters)
{
	uid_t target_uid = (uid_t)-1;
	char *pkgtype = NULL;
	char *pkgpath = NULL;
	char *args = NULL;
	char *reqkey = NULL;
	gchar **tmp_args = NULL;
	gsize args_count;
	int ret = -1;
	GVariant *value;
	int i = 0;
	int len = 0;

	g_variant_get(parameters, "(u&s&s@as)", &target_uid, &pkgtype, &pkgpath, &value);
	tmp_args = (gchar **)g_variant_get_strv(value, &args_count);

	for (i = 0; i < args_count; i++)
		len = len + strlen(tmp_args[i]) + 1;

	args = (char *)calloc(len, sizeof(char));
	if (args == NULL) {
		ERR("calloc failed");
		ret =  -1;
		goto catch;
	}

	for (i = 0; i < args_count; i++) {
		strncat(args, tmp_args[i], strlen(tmp_args[i]));
		strncat(args, " ", strlen(" "));
	}

	if (target_uid == (uid_t)-1 || pkgtype == NULL) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(is)", PKGMGR_R_ECOMM, ""));
		ret = -1;
		goto catch;
	}

	if (pkgpath == NULL) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(is)", PKGMGR_R_ECOMM, ""));
		ret = -1;
		goto catch;
	}

	reqkey = __generate_reqkey(pkgpath);
	if (reqkey == NULL) {
		ret = -1;
		goto catch;
	}

	if (_pm_queue_push(target_uid, reqkey, PKGMGR_REQUEST_TYPE_INSTALL, pkgtype,
				pkgpath, args)) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(is)", PKGMGR_R_ESYSTEM, ""));
		ret = -1;
		goto catch;
	}

	g_dbus_method_invocation_return_value(invocation,
			g_variant_new("(is)", PKGMGR_R_OK, reqkey));

	ret = 0;

catch:
	if (reqkey)
		free(reqkey);

	if (args)
		free(args);

	return ret;
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

static int __handle_request_enable_pkg(uid_t uid,
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

	if (_pm_queue_push(target_uid, "", PKGMGR_REQUEST_TYPE_ENABLE_PKG, "pkg",
				pkgid, "")) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(i)", PKGMGR_R_ESYSTEM));
		return -1;
	}

	g_dbus_method_invocation_return_value(invocation,
			g_variant_new("(i)", PKGMGR_R_OK));

	return 0;
}

static int __handle_request_disable_pkg(uid_t uid,
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

	if (_pm_queue_push(target_uid, "", PKGMGR_REQUEST_TYPE_DISABLE_PKG, "pkg",
				pkgid, "")) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(i)", PKGMGR_R_ESYSTEM));
		return -1;
	}

	g_dbus_method_invocation_return_value(invocation,
			g_variant_new("(i)", PKGMGR_R_OK));

	return 0;
}

static int __handle_request_enable_app(uid_t uid,
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

	if (_pm_queue_push(target_uid, "", PKGMGR_REQUEST_TYPE_ENABLE_APP, "pkg",
				pkgid, "")) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(i)", PKGMGR_R_ESYSTEM));
		return -1;
	}

	g_dbus_method_invocation_return_value(invocation,
			g_variant_new("(i)", PKGMGR_R_OK));

	return 0;
}

static int __handle_request_disable_app(uid_t uid,
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

	if (_pm_queue_push(target_uid, "", PKGMGR_REQUEST_TYPE_DISABLE_APP, "pkg",
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

static int __handle_request_generate_license_request(uid_t uid,
		GDBusMethodInvocation *invocation, GVariant *parameters)
{
	char *reqkey;
	char *resp_data = NULL;

	g_variant_get(parameters, "(&s)", &resp_data);
	if (resp_data == NULL) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(iss)", PKGMGR_R_ECOMM, "", ""));
		return -1;
	}

	reqkey = __generate_reqkey("drm");
	if (reqkey == NULL) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(iss)", PKGMGR_R_ENOMEM, "",
					""));
		return -1;
	}

	if (_pm_queue_push(uid, reqkey,
				PKGMGR_REQUEST_TYPE_GENERATE_LICENSE_REQUEST,
				"pkg", "", resp_data)) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(iss)", PKGMGR_R_ESYSTEM, "",
					""));
		free(reqkey);
		return -1;
	}

	if (!g_hash_table_insert(req_table, (gpointer)reqkey,
				(gpointer)invocation))
		ERR("reqkey already exists");

	return 0;
}

static int __handle_request_register_license(uid_t uid,
		GDBusMethodInvocation *invocation, GVariant *parameters)
{
	char *reqkey;
	char *resp_data = NULL;

	g_variant_get(parameters, "(&s)", &resp_data);
	if (resp_data == NULL) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(i)", PKGMGR_R_ECOMM));
		return -1;
	}

	reqkey = __generate_reqkey("drm");
	if (reqkey == NULL) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(i)", PKGMGR_R_ENOMEM));
		return -1;
	}

	if (_pm_queue_push(uid, reqkey, PKGMGR_REQUEST_TYPE_REGISTER_LICENSE,
				"pkg", "", resp_data)) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(i)", PKGMGR_R_ESYSTEM));
		free(reqkey);
		return -1;
	}

	if (!g_hash_table_insert(req_table, (gpointer)reqkey,
				(gpointer)invocation))
		ERR("reqkey already exists");

	return 0;
}

static int __handle_request_decrypt_package(uid_t uid,
		GDBusMethodInvocation *invocation, GVariant *parameters)
{
	char *reqkey;
	char *drm_file_path = NULL;
	char *decrypted_file_path = NULL;

	g_variant_get(parameters, "(&s&s)", &drm_file_path,
			&decrypted_file_path);
	if (drm_file_path == NULL || decrypted_file_path == NULL) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(i)", PKGMGR_R_ECOMM));
		return -1;
	}

	reqkey = __generate_reqkey("drm");
	if (reqkey == NULL) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(i)", PKGMGR_R_ENOMEM));
		return -1;
	}

	if (_pm_queue_push(uid, reqkey, PKGMGR_REQUEST_TYPE_DECRYPT_PACKAGE,
				"pkg", drm_file_path, decrypted_file_path)) {
		g_dbus_method_invocation_return_value(invocation,
				g_variant_new("(i)", PKGMGR_R_ESYSTEM));
		free(reqkey);
		return -1;
	}

	if (!g_hash_table_insert(req_table, (gpointer)reqkey,
				(gpointer)invocation))
		ERR("reqkey already exists");

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
	else if (g_strcmp0(method_name, "enable_pkg") == 0)
		ret = __handle_request_enable_pkg(uid, invocation, parameters);
	else if (g_strcmp0(method_name, "disable_pkg") == 0)
		ret = __handle_request_disable_pkg(uid, invocation, parameters);
	else if (g_strcmp0(method_name, "enable_app") == 0)
		ret = __handle_request_enable_app(uid, invocation, parameters);
	else if (g_strcmp0(method_name, "disable_app") == 0)
		ret = __handle_request_disable_app(uid, invocation, parameters);
	else if (g_strcmp0(method_name, "getsize") == 0)
		ret = __handle_request_getsize(uid, invocation, parameters);
	else if (g_strcmp0(method_name, "clearcache") == 0)
		ret = __handle_request_clearcache(uid, invocation, parameters);
	else if (g_strcmp0(method_name, "kill") == 0)
		ret = __handle_request_kill(uid, invocation, parameters);
	else if (g_strcmp0(method_name, "check") == 0)
		ret = __handle_request_check(uid, invocation, parameters);
	else if (g_strcmp0(method_name, "generate_license_request") == 0)
		ret = __handle_request_generate_license_request(uid, invocation,
				parameters);
	else if (g_strcmp0(method_name, "register_license") == 0)
		ret = __handle_request_register_license(uid, invocation,
				parameters);
	else if (g_strcmp0(method_name, "decrypt_package") == 0)
		ret = __handle_request_decrypt_package(uid, invocation,
				parameters);
	else
		ret = -1;

	if (ret == 0)
		g_idle_add(queue_job, NULL);
}

int __return_value_to_caller(const char *req_key, GVariant *result)
{
	GDBusMethodInvocation *invocation;

	invocation = (GDBusMethodInvocation *)g_hash_table_lookup(req_table,
			(gpointer)req_key);
	if (invocation == NULL) {
		ERR("no such request id");
		return -1;
	}

	g_dbus_method_invocation_return_value(invocation, result);
	g_hash_table_remove(req_table, (gpointer)req_key);

	return 0;
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

	req_table = g_hash_table_new_full(g_str_hash, g_str_equal,
			free, NULL);
	if (req_table == NULL)
		return -1;

	return 0;
}

void __fini_request_handler(void)
{
	g_hash_table_destroy(req_table);
	g_bus_unown_name(owner_id);
	g_dbus_node_info_unref(instropection_data);
}
