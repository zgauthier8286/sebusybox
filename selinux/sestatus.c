/*
 * sestatus
 *   Port to busybox: KaiGai Kohei <kaigai@kaigai.gr.jp>
 *   based on policycoreutils-1.32
 * 
 * Copyright 1999-2004 Gentoo Technologies, Inc.
 * Distributed under the terms of the GNU General Public License v2
 * $Header: /home/cvsroot/gentoo-projects/hardened/policycoreutils-extra/src/sestatus.c,v 1.10 2004/03/26 19:25:52 pebenito Exp $
 * Patch provided by Steve Grubb
 */
#include "busybox.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <selinux/selinux.h>
#include <selinux/get_default_type.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <libgen.h>
#include <ctype.h>

#define PROC_BASE "/proc"
#define MAX_CHECK 50
#define CONF "/etc/sestatus.conf"

/* conf file sections */
#define PROCS "[process]"
#define FILES "[files]"

/* buffer size for cmp_cmdline */
#define BUFSIZE 255

/* column to put the output (must be a multiple of 8) */
static unsigned int COL = 32;

extern char *selinux_mnt;

int cmp_cmdline(const char *command, int pid)
{

	char buf[BUFSIZE];
	char filename[BUFSIZE];

	memset(buf, '\0', BUFSIZE);

	/* first read the proc entry */
	sprintf(filename, "%s/%d/exe", PROC_BASE, pid);

	if (readlink(filename, buf, BUFSIZE) < 0)
		return 0;

	if (buf[BUFSIZE - 1] != '\0')
		buf[BUFSIZE - 1] = '\0';

	/* check if this is the command we're looking for. */
	if (strcmp(command, buf) == 0)
		return 1;
	else
		return 0;
}

int pidof(const char *command)
{
/* inspired by killall5.c from psmisc */
	DIR *dir;
	struct dirent *de;
	int pid, ret = -1, self = getpid();

	if (!(dir = opendir(PROC_BASE))) {
		perror(PROC_BASE);
		return -1;
	}

	while ((de = readdir(dir)) != NULL) {
		errno = 0;
		pid = (int)strtol(de->d_name, (char **)NULL, 10);
		if (errno || pid == 0 || pid == self)
			continue;
		if (cmp_cmdline(command, pid)) {
			ret = pid;
			break;
		}
	}

	closedir(dir);
	return ret;
}

void load_checks(char *pc[], int *npc, char *fc[], int *nfc)
{

	FILE *fp = fopen(CONF, "r");
	char buf[255], *bufp;
	int buf_len, section = -1;
	int proclen = strlen(PROCS);
	int filelen = strlen(FILES);

	if (fp == NULL) {
		printf("\nUnable to open %s.\n", CONF);
		return;
	}

	while (!feof(fp)) {
		if (!fgets(buf, sizeof buf, fp))
			break;

		buf_len = strlen(buf);
		if (buf[buf_len - 1] == '\n')
			buf[buf_len - 1] = 0;

		bufp = buf;
		while (*bufp && isspace(*bufp)) {
			bufp++;
			buf_len--;
		}

		if (*bufp == '#')
			/* skip comments */
			continue;

		if (*bufp) {
			if (!(*bufp))
				goto out;

			if (strncmp(bufp, PROCS, proclen) == 0)
				section = 0;
			else if (strncmp(bufp, FILES, filelen) == 0)
				section = 1;
			else {
				switch (section) {
				case 0:
					if (*npc >= MAX_CHECK)
						break;
					pc[*npc] =
					    (char *)malloc((buf_len) *
							   sizeof(char));
					memcpy(pc[*npc], bufp, buf_len);
					(*npc)++;
					bufp = NULL;
					break;
				case 1:
					if (*nfc >= MAX_CHECK)
						break;
					fc[*nfc] =
					    (char *)malloc((buf_len) *
							   sizeof(char));
					memcpy(fc[*nfc], bufp, buf_len);
					(*nfc)++;
					bufp = NULL;
					break;
				default:
					/* ignore lines before a section */
					printf("Line not in a section: %s.\n",
					       buf);
					break;
				}
			}
		}
	}
      out:
	fclose(fp);
	return;
}

void printf_tab(const char *outp)
{
	char buf[20];
	snprintf(buf, sizeof(buf), "%%-%us", COL);
	printf(buf, outp);

}

#define OPT_SESTATUS_VERBOSE		(1<<0)	/* -v */
#define OPT_SESTATUS_SHOWBOOLS		(1<<1)	/* -b */

int sestatus_main(int argc, char **argv)
{
	/* these vars are reused several times */
	int rc, i, c;
	unsigned long opts;
	char *context;

	/* files that need context checks */
	char *fc[MAX_CHECK];
	char *cterm = ttyname(0);
	int nfc = 0;
	struct stat m;

	/* processes that need context checks */
	char *pc[MAX_CHECK];
	int npc = 0;

	/* booleans */
	char **bools;
	int nbool;

	int verbose = 0;
	int show_bools = 0;

	/* policy */
	const char *pol_name;
	char *pol_path;

	opts = bb_getopt_ulflags(argc, argv, "vb");
	if (opts & BB_GETOPT_ERROR)
		bb_show_usage();
	if (opts & OPT_SESTATUS_VERBOSE)
		verbose = 1;
	if (opts & OPT_SESTATUS_SHOWBOOLS)
		show_bools = 1;

	printf_tab("SELinux status:");
	rc = is_selinux_enabled();

	switch (rc) {
	case 1:
		printf("enabled\n");
		break;
	case 0:
		printf("disabled\n");
		return 0;
		break;
	default:
		printf("unknown (%s)\n", strerror(errno));
		return 0;
		break;
	}

	printf_tab("SELinuxfs mount:");
	if (selinux_mnt != NULL) {
		printf("%s\n", selinux_mnt);
	} else {
		printf("not mounted\n\n");
		printf("Please mount selinuxfs for proper results.\n");
		return -1;
	}

	printf_tab("Current mode:");
	rc = security_getenforce();
	switch (rc) {
	case 1:
		printf("enforcing\n");
		break;
	case 0:
		printf("permissive\n");
		break;
	default:
		printf("unknown (%s)\n", strerror(errno));
		break;
	}

	printf_tab("Mode from config file:");
	if (selinux_getenforcemode(&rc) == 0) {
		switch (rc) {
		case 1:
			printf("enforcing\n");
			break;
		case 0:
			printf("permissive\n");
			break;
		case -1:
			printf("disabled\n");
			break;
		}
	} else {
		printf("error (%s)\n", strerror(errno));
	}

	rc = security_policyvers();
	printf_tab("Policy version:");
	if (rc < 0)
		printf("unknown (%s)\n", strerror(errno));
	else
		printf("%d\n", rc);

	/* Dump all the path information */
	printf_tab("Policy from config file:");
	pol_path = strdup(selinux_policy_root());
	if (pol_path) {
		pol_name = basename(pol_path);
		puts(pol_name);
		free(pol_path);
	} else {
		printf("error (%s)\n", strerror(errno));
	}

	if (show_bools) {
		/* show booleans */
		if (security_get_boolean_names(&bools, &nbool) >= 0) {
			printf("\nPolicy booleans:\n");

			for (i = 0; i < nbool; i++) {
				if (strlen(bools[i]) + 1 > COL)
					COL = strlen(bools[i]) + 1;
			}
			for (i = 0; i < nbool; i++) {
				printf_tab(bools[i]);

				rc = security_get_boolean_active(bools[i]);
				switch (rc) {
				case 1:
					printf("on");
					break;
				case 0:
					printf("off");
					break;
				default:
					printf("unknown (%s)", strerror(errno));
					break;
				}
				c = security_get_boolean_pending(bools[i]);
				if (c != rc)
					switch (c) {
					case 1:
						printf(" (activate pending)");
						break;
					case 0:
						printf(" (inactivate pending)");
						break;
					default:
						printf(" (pending error: %s)",
						       strerror(errno));
						break;
					}
				printf("\n");

				/* free up the booleans */
				free(bools[i]);
			}
			free(bools);
		}
	}
	/* only show contexts if -v is given */
	if (!verbose)
		return 0;

	load_checks(pc, &npc, fc, &nfc);

	printf("\nProcess contexts:\n");

	printf_tab("Current context:");
	if (getcon(&context) >= 0) {
		printf("%s\n", context);
		freecon(context);
	} else
		printf("unknown (%s)\n", strerror(errno));

	printf_tab("Init context:");
	if (getpidcon(1, &context) >= 0) {
		printf("%s\n", context);
		freecon(context);
	} else
		printf("unknown (%s)\n", strerror(errno));

	for (i = 0; i < npc; i++) {
		rc = pidof(pc[i]);
		if (rc > 0) {
			if (getpidcon(rc, &context) < 0)
				continue;

			printf_tab(pc[i]);
			printf("%s\n", context);
			freecon(context);
		}
	}

	printf("\nFile contexts:\n");

	/* controlling term */
	printf_tab("Controlling term:");
	if (lgetfilecon(cterm, &context) >= 0) {
		printf("%s\n", context);
		freecon(context);
	} else {
		printf("unknown (%s)\n", strerror(errno));
	}

	for (i = 0; i < nfc; i++) {
		if (lgetfilecon(fc[i], &context) >= 0) {
			printf_tab(fc[i]);

			/* check if this is a symlink */
			if (lstat(fc[i], &m)) {
				printf
				    ("%s (could not check link status (%s)!)\n",
				     context, strerror(errno));
				freecon(context);
				continue;
			}
			if (S_ISLNK(m.st_mode)) {
				/* print link target context */
				printf("%s -> ", context);
				freecon(context);

				if (getfilecon(fc[i], &context) >= 0) {
					printf("%s\n", context);
					freecon(context);
				} else {
					printf("unknown (%s)\n",
					       strerror(errno));
				}
			} else {
				printf("%s\n", context);
				freecon(context);
			}
		}
	}

	return 0;
}
