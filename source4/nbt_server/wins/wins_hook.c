/* 
   Unix SMB/CIFS implementation.

   wins hook feature, we run a specified script
   which can then do some custom actions

   Copyright (C) Stefan Metzmacher	2005
      
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "nbt_server/nbt_server.h"
#include "nbt_server/wins/winsdb.h"
#include "system/filesys.h"

static const char *wins_hook_action_string(enum wins_hook_action action)
{
	switch (action) {
	case WINS_HOOK_ADD:	return "add";
	case WINS_HOOK_MODIFY:	return "refresh";
	case WINS_HOOK_DELETE:	return "delete";
	}

	return "unknown";
}

void wins_hook(struct winsdb_handle *h, const struct winsdb_record *rec, 
	       enum wins_hook_action action, const char *wins_hook_script)
{
	uint32_t i, length;
	int child;
	char **argv = NULL;
	uint32_t argc = 0;
	TALLOC_CTX *tmp_mem = NULL;

	if (!wins_hook_script || !wins_hook_script[0]) return;

	tmp_mem = talloc_new(h);
	if (!tmp_mem) goto failed;

	length = winsdb_addr_list_length(rec->addresses);

	if (action == WINS_HOOK_MODIFY && length < 1) {
		action = WINS_HOOK_DELETE;
	}

	/* Build argument array for direct execution (no shell) to prevent command injection */
	/* argv[0] = script, argv[1] = action, argv[2] = name, argv[3] = type, argv[4] = expire_time, argv[5..n] = addresses, argv[n+1] = NULL */
	argc = 5 + length + 1; /* script + action + name + type + expire_time + addresses + NULL */
	argv = talloc_zero_array(tmp_mem, char *, argc);
	if (!argv) goto failed;

	argv[0] = talloc_strdup(tmp_mem, wins_hook_script);
	if (!argv[0]) goto failed;

	argv[1] = talloc_strdup(tmp_mem, wins_hook_action_string(action));
	if (!argv[1]) goto failed;

	argv[2] = talloc_strdup(tmp_mem, rec->name->name);
	if (!argv[2]) goto failed;

	argv[3] = talloc_asprintf(tmp_mem, "%02x", rec->name->type);
	if (!argv[3]) goto failed;

	argv[4] = talloc_asprintf(tmp_mem, "%ld", (long int) rec->expire_time);
	if (!argv[4]) goto failed;

	for (i=0; rec->addresses[i]; i++) {
		argv[5 + i] = talloc_strdup(tmp_mem, rec->addresses[i]->address);
		if (!argv[5 + i]) goto failed;
	}

	argv[5 + i] = NULL; /* NULL terminate the array */

	DEBUG(10,("call wins hook '%s' with %d arguments\n", wins_hook_script, argc - 1));

	/* signal handling in posix really sucks - doing this in a library
	   affects the whole app, but what else to do?? */
	signal(SIGCHLD, SIG_IGN);

	child = fork();
	if (child == (pid_t)-1) {
		goto failed;
	}

	if (child == 0) {
/* TODO: close file handles */
		execv(argv[0], argv);
		_exit(0);
	}

	talloc_free(tmp_mem);
	return;
failed:
	talloc_free(tmp_mem);
	DEBUG(0,("FAILED: calling wins hook '%s'\n", wins_hook_script));
}
