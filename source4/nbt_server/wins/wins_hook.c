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

/*
 * SECURITY VULNERABILITY FIXED: Command Injection via WINS Hook Script Invocation
 * 
 * VULNERABILITY DESCRIPTION:
 * The previous implementation of this function was vulnerable to command injection attacks.
 * The vulnerability occurred because:
 * 1. NetBIOS names (rec->name->name) and IP addresses (rec->addresses[i]->address) 
 *    are received from network packets and are attacker-controlled
 * 2. These values were directly concatenated into a shell command string without 
 *    any sanitization, escaping, or validation
 * 3. The command was executed via execl("/bin/sh", "sh", "-c", cmd, NULL), which 
 *    passes the entire string to a shell for interpretation
 * 4. Shell metacharacters in the attacker-controlled fields (like ; | & $ ` etc.) 
 *    would be interpreted by the shell, allowing arbitrary command execution
 * 
 * ATTACK VECTOR DATA FLOW:
 * Network packet -> nbtd_winsserver_register() -> wins_register_new()/wins_update_ttl() 
 * -> winsdb_add/modify/delete() -> wins_hook() -> execl("/bin/sh", "-c", malicious_cmd)
 * 
 * EXAMPLE ATTACK:
 * An attacker could register a NetBIOS name like: "test; rm -rf /; #"
 * This would result in a command like: "/path/to/script add test; rm -rf /; # 00 123456 192.168.1.1"
 * The shell would execute: script, then "rm -rf /", then ignore the rest as a comment
 * 
 * SECURE IMPLEMENTATION APPROACH:
 * The fix replaces shell command string construction and execution with direct process 
 * execution using execv() and an argument array. This approach:
 * 1. Completely avoids shell interpretation of any data
 * 2. Treats each parameter as a literal string argument
 * 3. Prevents any shell metacharacter interpretation
 * 4. Maintains the same functional interface for hook scripts
 * 5. Preserves all original functionality while eliminating the security risk
 */
void wins_hook(struct winsdb_handle *h, const struct winsdb_record *rec, 
	       enum wins_hook_action action, const char *wins_hook_script)
{
	uint32_t i, length;
	int child;
	
	/*
	 * SECURE IMPLEMENTATION VARIABLES:
	 * Instead of building a single command string, we build an array of string arguments
	 * that will be passed directly to execv() without shell interpretation.
	 */
	char **argv = NULL;           /* Argument array for execv() - prevents shell injection */
	char *action_str = NULL;      /* String representation of the action (add/refresh/delete) */
	char *name_str = NULL;        /* Copy of NetBIOS name (potentially attacker-controlled) */
	char *type_str = NULL;        /* Hexadecimal string of NetBIOS name type */
	char *expire_str = NULL;      /* String representation of expiration timestamp */
	
	TALLOC_CTX *tmp_mem = NULL;

	/* Early return if no hook script is configured */
	if (!wins_hook_script || !wins_hook_script[0]) return;

	/*
	 * MEMORY MANAGEMENT:
	 * Create a temporary memory context for all allocations in this function.
	 * This ensures proper cleanup on both success and failure paths.
	 */
	tmp_mem = talloc_new(h);
	if (!tmp_mem) goto failed;

	/* Count the number of IP addresses associated with this WINS record */
	length = winsdb_addr_list_length(rec->addresses);

	/*
	 * BUSINESS LOGIC: Convert modify operations with no addresses to delete operations.
	 * This maintains the original behavior where refreshing a record with no addresses
	 * is treated as a deletion.
	 */
	if (action == WINS_HOOK_MODIFY && length < 1) {
		action = WINS_HOOK_DELETE;
	}

	/*
	 * SECURE ARGUMENT PREPARATION:
	 * Instead of concatenating strings into a shell command, we prepare individual
	 * string arguments that will be passed directly to the hook script.
	 * Each argument is safely isolated and cannot be interpreted as shell commands.
	 */
	
	/* Convert action enum to string representation */
	action_str = talloc_strdup(tmp_mem, wins_hook_action_string(action));
	if (!action_str) goto failed;

	/*
	 * CRITICAL SECURITY NOTE: NetBIOS name handling
	 * The rec->name->name field originates from network packets and is attacker-controlled.
	 * In the vulnerable version, this could contain shell metacharacters like:
	 * "test; rm -rf /; #" or "test`id`" or "test$(whoami)" etc.
	 * By copying it as a separate argument, we ensure it's treated as literal data.
	 */
	name_str = talloc_strdup(tmp_mem, rec->name->name);
	if (!name_str) goto failed;

	/* Convert NetBIOS name type to hexadecimal string */
	type_str = talloc_asprintf(tmp_mem, "%02x", rec->name->type);
	if (!type_str) goto failed;

	/* Convert expiration timestamp to string */
	expire_str = talloc_asprintf(tmp_mem, "%ld", (long int) rec->expire_time);
	if (!expire_str) goto failed;

	/*
	 * ARGUMENT ARRAY CONSTRUCTION:
	 * Build the argv array for execv(). The array contains:
	 * argv[0] = script path (executable name)
	 * argv[1] = action string ("add", "refresh", or "delete")
	 * argv[2] = NetBIOS name (potentially attacker-controlled, now safe)
	 * argv[3] = NetBIOS type (hexadecimal)
	 * argv[4] = expiration time (decimal timestamp)
	 * argv[5..4+length] = IP addresses (potentially attacker-controlled, now safe)
	 * argv[5+length] = NULL (required terminator for execv)
	 */
	argv = talloc_array(tmp_mem, char *, 6 + length);
	if (!argv) goto failed;

	/* Set the script path as argv[0] (executable name) */
	argv[0] = talloc_strdup(tmp_mem, wins_hook_script);
	if (!argv[0]) goto failed;
	
	/* Set the fixed arguments */
	argv[1] = action_str;
	argv[2] = name_str;
	argv[3] = type_str;
	argv[4] = expire_str;

	/*
	 * CRITICAL SECURITY NOTE: IP address handling
	 * The rec->addresses[i]->address fields also originate from network packets
	 * and are attacker-controlled. In the vulnerable version, an attacker could
	 * register IP addresses like: "192.168.1.1; rm -rf /; #"
	 * By treating each address as a separate argument, we ensure safe handling.
	 */
	for (i = 0; rec->addresses[i]; i++) {
		argv[5 + i] = talloc_strdup(tmp_mem, rec->addresses[i]->address);
		if (!argv[5 + i]) goto failed;
	}
	
	/* NULL-terminate the argument array (required by execv) */
	argv[5 + i] = NULL;

	/*
	 * DEBUG LOGGING:
	 * Log the hook invocation for debugging. We reconstruct the command-like
	 * representation for logging purposes, but this is only for display -
	 * the actual execution uses the secure argv array.
	 */
	DEBUG(10,("call wins hook '%s %s %s %s %s", 
		  argv[0], argv[1], argv[2], argv[3], argv[4]));
	for (i = 0; rec->addresses[i]; i++) {
		DEBUG(10,(" %s", argv[5 + i]));
	}
	DEBUG(10,("'\n"));

	/*
	 * PROCESS EXECUTION:
	 * Fork a child process to execute the hook script. This maintains the
	 * original asynchronous behavior where the hook doesn't block the main process.
	 */
	
	/* signal handling in posix really sucks - doing this in a library
	   affects the whole app, but what else to do?? */
	signal(SIGCHLD, SIG_IGN);

	child = fork();
	if (child == (pid_t)-1) {
		goto failed;
	}

	if (child == 0) {
		/*
		 * CHILD PROCESS - SECURE EXECUTION:
		 * Use execv() instead of execl("/bin/sh", "sh", "-c", cmd, NULL).
		 * This is the core security fix:
		 * 
		 * OLD (VULNERABLE): execl("/bin/sh", "sh", "-c", cmd, NULL)
		 *   - Passes entire command string to shell for interpretation
		 *   - Shell parses and interprets metacharacters
		 *   - Enables command injection via shell metacharacters
		 * 
		 * NEW (SECURE): execv(wins_hook_script, argv)
		 *   - Directly executes the script without shell involvement
		 *   - Each argument is passed as literal data
		 *   - No shell interpretation or metacharacter processing
		 *   - Completely prevents command injection
		 * 
		 * SECURITY BENEFIT:
		 * Even if an attacker controls NetBIOS names or IP addresses containing
		 * shell metacharacters like "; rm -rf /", these are now passed as literal
		 * string arguments to the hook script, not interpreted as shell commands.
		 */
/* TODO: close file handles */
		execv(wins_hook_script, argv);
		_exit(0);
	}

	/*
	 * PARENT PROCESS - CLEANUP:
	 * Free the temporary memory context, which automatically frees all
	 * allocated strings and the argv array.
	 */
	talloc_free(tmp_mem);
	return;

failed:
	/*
	 * ERROR HANDLING:
	 * Clean up memory and log the failure. The error path ensures no memory
	 * leaks occur even when allocation failures happen during argument preparation.
	 */
	talloc_free(tmp_mem);
	DEBUG(0,("FAILED: calling wins hook '%s'\n", wins_hook_script));
}
