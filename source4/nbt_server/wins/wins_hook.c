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
	uint32_t argc;
	TALLOC_CTX *tmp_mem = NULL;

	if (!wins_hook_script || !wins_hook_script[0]) return;

	tmp_mem = talloc_new(h);
	if (!tmp_mem) goto failed;

	length = winsdb_addr_list_length(rec->addresses);

	if (action == WINS_HOOK_MODIFY && length < 1) {
		action = WINS_HOOK_DELETE;
	}

	/* Build argv array instead of concatenating into shell command
	 * argv[0] = script path
	 * argv[1] = action
	 * argv[2] = name
	 * argv[3] = type (hex)
	 * argv[4] = expire_time
	 * argv[5..n] = addresses
	 * argv[n+1] = NULL
	 */
	argc = 5 + length;
	argv = talloc_array(tmp_mem, char *, argc + 1);
	if (!argv) goto failed;

	argv[0] = talloc_strdup(argv, wins_hook_script);
	argv[1] = talloc_strdup(argv, wins_hook_action_string(action));
	argv[2] = talloc_strdup(argv, rec->name->name);
	argv[3] = talloc_asprintf(argv, "%02x", rec->name->type);
	argv[4] = talloc_asprintf(argv, "%ld", (long int) rec->expire_time);

	if (!argv[0] || !argv[1] || !argv[2] || !argv[3] || !argv[4]) {
		goto failed;
	}

	for (i=0; rec->addresses[i]; i++) {
		argv[5 + i] = talloc_strdup(argv, rec->addresses[i]->address);
		if (!argv[5 + i]) goto failed;
	}
	argv[argc] = NULL;

	DEBUG(10,("call wins hook '%s' with action '%s', name '%s'\n", 
		  wins_hook_script, wins_hook_action_string(action), rec->name->name));

	/* signal handling in posix really sucks - doing this in a library
	   affects the whole app, but what else to do?? */
	signal(SIGCHLD, SIG_IGN);

	child = fork();
	if (child == (pid_t)-1) {
		goto failed;
	}

	if (child == 0) {
/* TODO: close file handles */
		execv(wins_hook_script, argv);
		_exit(0);
	}

	talloc_free(tmp_mem);
	return;
failed:
	talloc_free(tmp_mem);
	DEBUG(0,("FAILED: calling wins hook '%s'\n", wins_hook_script));
}
