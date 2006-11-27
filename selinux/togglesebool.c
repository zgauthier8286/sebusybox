/*
 * togglesebool
 * 
 * Based on libselinux 1.33.1
 * Port to BusyBox  Hiroshi Shinji <shiroshi@my.email.ne.jp>
 *
 * Copyright 1999-2004 Gentoo Technologies, Inc.
 * Distributed under the terms of the GNU General Public License v2
 * $Header: /var/cvsroot/gentoo-projects/hardened/policycoreutils-extra/src/toggle_bool.c,v 1.2 2004/06/18 04:09:04 pebenito Exp $
 */

#include "busybox.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <errno.h>
#include <selinux/selinux.h>
#include <syslog.h>
#include <pwd.h>
#include <string.h>

/* Attempt to rollback the transaction. No need to check error
   codes since this is rolling back something that blew up. */
void rollback(int argc, char **argv)
{
	int i;

	for (i = 1; i < argc; i++)
		security_set_boolean(argv[i],
				     security_get_boolean_active(argv[i]));
	exit(1);
}

int togglesebool_main(int argc, char **argv)
{

	int rc, i, commit = 0;

	if (is_selinux_enabled() <= 0) {
		bb_error_msg_and_die("SELinux is disabled");
	}

	if (argc < 2) {
		bb_show_usage();
	}

	for (i = 1; i < argc; i++) {
		printf("%s: ", argv[i]);
		rc = security_get_boolean_active(argv[i]);
		switch (rc) {
		case 1:
			if (security_set_boolean(argv[i], 0) >= 0) {
				printf("inactive\n");
				commit++;
			} else {
				printf("%s - rolling back all changes\n",
				       strerror(errno));
				rollback(i, argv);
			}
			break;
		case 0:
			if (security_set_boolean(argv[i], 1) >= 0) {
				printf("active\n");
				commit++;
			} else {
				printf("%s - rolling back all changes\n",
				       strerror(errno));
				rollback(i, argv);
			}
			break;
		default:
			if (errno == ENOENT)
				printf
				    ("Boolean does not exist - rolling back all changes.\n");
			else
				printf("%s - rolling back all changes.\n",
				       strerror(errno));
			rollback(i, argv);
			break;	/* Not reached. */
		}
	}

	if (commit > 0) {
		if (security_commit_booleans() < 0) {
			printf("Commit failed. (%s)  No change to booleans.\n",
			       strerror(errno));
		} else {
			/* syslog all the changes */
			struct passwd *pwd = getpwuid(getuid());
			for (i = 1; i < argc; i++) {
				if (pwd && pwd->pw_name)
					syslog(LOG_NOTICE,
					       "The %s policy boolean was toggled by %s",
					       argv[i], pwd->pw_name);
				else
					syslog(LOG_NOTICE,
					       "The %s policy boolean was toggled by uid:%d",
					       argv[i], getuid());

			}
			return 0;
		}
	}
	return 1;
}
