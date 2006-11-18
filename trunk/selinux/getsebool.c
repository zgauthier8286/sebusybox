/*
 * getsebool
 *
 * Based on libselinux 1.33.1
 * Port to BusyBox  Hiroshi Shinji <shiroshi@my.email.ne.jp>
 *
 */

#include "busybox.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <selinux/selinux.h>

#define GETSEBOOL_OPT_ALL	1

int getsebool_main(int argc, char **argv)
{
	int i, rc = 0, active, pending, len = 0;
	char **names;
	unsigned long opt;

	opt =  bb_getopt_ulflags(argc, argv, "a");

	if(opt & BB_GETOPT_ERROR) {
		bb_show_usage();
	}
	if(opt & GETSEBOOL_OPT_ALL) {
		if (argc > 2)
			bb_show_usage();
		if (is_selinux_enabled() <= 0) {
			bb_error_msg_and_die("SELinux is disabled");
		}
		errno = 0;
		rc = security_get_boolean_names(&names, &len);
		if (rc) {
			bb_error_msg_and_die("Unable to get boolean names:  %s", strerror(errno));
		}
		if (!len) {
			printf("No booleans\n");
			return 0;
		}
	}

	if (is_selinux_enabled() <= 0) {
		bb_error_msg_and_die("SELinux is disabled");
	}

	if (!len) {
		if (argc < 2)
			bb_show_usage();
		len = argc - 1;
		names = malloc(sizeof(char *) * len);
		if (!names) {
			bb_error_msg_and_die("out of memory");
		}
		for (i = 0; i < len; i++) {
			names[i] = strdup(argv[i + 1]);
			if (!names[i]) {
				bb_error_msg_and_die("out of memory");
			}
		}
	}

	for (i = 0; i < len; i++) {
		active = security_get_boolean_active(names[i]);
		if (active < 0) {
			bb_error_msg("Error getting active value for %s",
				names[i]);
			rc = -1;
			goto out;
		}
		pending = security_get_boolean_pending(names[i]);
		if (pending < 0) {
			bb_error_msg("Error getting pending value for %s",
				names[i]);
			rc = -1;
			goto out;
		}
		if (pending != active) {
			printf("%s --> %s pending: %s\n", names[i],
			       (active ? "on" : "off"),
			       (pending ? "on" : "off"));
		} else {
			printf("%s --> %s\n", names[i],
			       (active ? "on" : "off"));
		}
	}

      out:
	for (i = 0; i < len; i++)
		free(names[i]);
	free(names);
	return rc;
}
