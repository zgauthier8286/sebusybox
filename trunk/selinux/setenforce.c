/*
 * setenforce
 *
 * Based on libselinux 1.33.1
 * Port to BusyBox  Hiroshi Shinji <shiroshi@my.email.ne.jp>
 *
 */

#include "busybox.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <selinux/selinux.h>

int setenforce_main(int argc, char **argv)
{
	int rc = 0;
	if (argc != 2) {
		bb_show_usage();
	}

	if (is_selinux_enabled() <= 0) {
		bb_error_msg("SELinux is disabled");
		return 1;
	}
	if (strlen(argv[1]) == 1 && (argv[1][0] == '0' || argv[1][0] == '1')) {
		rc = security_setenforce(atoi(argv[1]));
	} else {
		if (strcasecmp(argv[1], "enforcing") == 0) {
			rc = security_setenforce(1);
		} else if (strcasecmp(argv[1], "permissive") == 0) {
			rc = security_setenforce(0);
		} else
			bb_show_usage();
	}
	if (rc < 0) {
		bb_error_msg("setenforce() failed");
		return 2;
	}
	return 0;
}
