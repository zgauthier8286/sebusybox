/*
 * getenforce
 *
 * Based on libselinux 1.33.1
 * Port to BusyBox  Hiroshi Shinji <shiroshi@my.email.ne.jp>
 *
 */

#include "busybox.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <selinux/selinux.h>

int getenforce_main(int argc, char **argv)
{
	int rc;

	rc = is_selinux_enabled();
	if (rc < 0) {
		bb_error_msg("is_selinux_enabled() failed");
		return 2;
	}
	if (rc == 1) {
		rc = security_getenforce();
		if (rc < 0) {
			bb_error_msg("getenforce() failed");
			return 2;
		}

		if (rc)
			puts("Enforcing");
		else
			puts("Permissive");
	} else {
		puts("Disabled");
	}

	return 0;
}
