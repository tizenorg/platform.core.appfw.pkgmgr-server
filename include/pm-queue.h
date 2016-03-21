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





#ifndef _PM_QUEUE_H_
#define _PM_QUEUE_H_

#include "pkgmgr-server.h"

#define STATUS_FILE	"/etc/package-manager/server/queue_status"
/* #define STATUS_FILE   "./queue_status" */

typedef struct _pm_queue_data {
	pm_dbus_msg *msg;
	struct _pm_queue_data *next;
} pm_queue_data;

typedef struct queue_info_map_t {
	char pkgtype[MAX_PKG_TYPE_LEN];
	char backend[MAX_PKG_NAME_LEN];
	int queue_slot;
	pm_queue_data *head;
} queue_info_map;

#define MAX_QUEUE_NUM 128

int _pm_queue_init(void);
int _pm_queue_push(uid_t uid, const char *req_id, int req_type,
		const char *queue_type, const char *pkgid, const char *argv);
/*position specifies the queue from which to pop request*/
pm_dbus_msg *_pm_queue_pop(int position);
void _pm_queue_final();
void _pm_queue_delete(pm_dbus_msg *item);
pm_queue_data *_add_node();
void _save_queue_status(pm_dbus_msg *item, char *status);
void _print_queue(int position);

#endif				/* _PM_QUEUE_H_ */
