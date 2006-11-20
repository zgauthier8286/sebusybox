/*
 * chcon -- based on coreutils-5.97-13
 *
 * Author: ????
 * Port to busybox: KaiGai Kohei <kaigai@kaigai.gr.jp>
 * 
 * Copyright (C) 2006 KaiGai Kohei <kaigai@kaigai.gr.jp>
 * Licensed under the GPL v2 or later, see the file LICENSE
 * in this tarball.
 */
#include "busybox.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <selinux/selinux.h>
#include <selinux/context.h>

#ifdef CONFIG_FEATURE_CHCON_LONG_OPTIONS
static struct option chcon_options[] = {
	{"recursive",	0,	NULL,	'R'},
	{"changes",	0,	NULL,	'c'},
	{"no-dereference",	0,	NULL,	'h'},
	{"silent",	0,	NULL,	'f'},
	{"quiet",	0,	NULL,	'f'},
	{"reference",	1,	NULL,	'\n' },	/* no short option */
	{"user",	1,	NULL,	'u' },
	{"role",	1,	NULL,	'r' },
	{"type",	1,	NULL,	't' },
	{"range",	1,	NULL,	'l' },
	{"verbose",	0,	NULL,	'v' },
	{"help",	0,	NULL,	'?' },
	{"version",	0,	NULL,	'\b' },	/* no short option */
	{NULL,		0,	NULL,	0 },
};
#endif

#define OPT_CHCON_RECURSIVE		(1<<0)	/* 'R' */
#define OPT_CHCON_CHANHES		(1<<1)	/* 'c' */
#define OPT_CHCON_NODEREFERENCE		(1<<2)	/* 'h' */
#define OPT_CHCON_QUIET			(1<<3)	/* 'f' */
#define OPT_CHCON_REFERENCE		(1<<4)	/* '\n' */
#define OPT_CHCON_USER			(1<<5)	/* 'u' */
#define OPT_CHCON_ROLE			(1<<6)	/* 'r' */
#define OPT_CHCON_TYPE			(1<<7)	/* 't' */
#define OPT_CHCON_RANGE			(1<<8)	/* 'l' */
#define OPT_CHCON_VERBOSE		(1<<9)	/* 'v' */
#define OPT_CHCON_HELP			(1<<10)	/* '?' */
#define OPT_CHCON_VERSION		(1<<11)	/* '\b' */
#define OPT_CHCON_COMPONENT_SPECIFIED	(OPT_CHCON_USER | OPT_CHCON_ROLE | OPT_CHCON_TYPE | OPT_CHCON_RANGE)

static char *user = NULL;
static char *role = NULL;
static char *type = NULL;
static char *range = NULL;
static char *specified_context = NULL;
static char **target_files = NULL;

static int change_dir_context(const char *dir_name, unsigned long opts);
static int change_file_context(const char *file, unsigned long opts);

static unsigned long chcon_parse_options(int argc, char *argv[])
{
	unsigned long opts;
	char *reference_file = NULL;

#ifdef CONFIG_FEATURE_CHCON_LONG_OPTIONS
	bb_applet_long_options = chcon_options;
#endif
	opts = bb_getopt_ulflags(argc, argv, "Rchf\n:u:r:t:l:v?\b",
				 &reference_file,
				 &user,
				 &role,
				 &type,
				 &range);

	if (opts & OPT_CHCON_VERSION) {
		printf("%s - busybox %s (build: %s)\n",
		       argv[0], BB_VER, BB_BT);
		exit(0);
	}

	if (opts & (OPT_CHCON_HELP | BB_GETOPT_ERROR))
		bb_show_usage();

	if ((opts & OPT_CHCON_QUIET) && (opts & OPT_CHCON_VERBOSE)) {
		fprintf(stderr, "could not specify quiet and verbose option same time\n");
		bb_show_usage();
	}

	if ((opts & OPT_CHCON_REFERENCE) && (opts & OPT_CHCON_COMPONENT_SPECIFIED)) {
		fprintf(stderr, "conflicting security context specifiers given\n");
		bb_show_usage();
	} else if (opts & OPT_CHCON_REFERENCE) {
		/* FIXME: lgetfilecon() should be used when '-h' is specified. */
		if (getfilecon(reference_file, &specified_context) < 0) {
			fprintf(stderr, "getfilecon('%s'), errno=%d (%s)\n",
				reference_file, errno, strerror(errno));
			exit(1);
		}
	} else if ((opts & OPT_CHCON_COMPONENT_SPECIFIED) == 0) {
		specified_context = argv[optind++];
		if (!specified_context) {
			fprintf(stderr, "too few arguments\n");
			bb_show_usage();
		}
	}
	target_files = argv + optind;
	if (!*target_files) {
		fprintf(stderr, "too few arguments\n");
		bb_show_usage();
	}
	return opts;
}

static context_t compute_context_from_mask(security_context_t context, unsigned long opts)
{
	context_t new_context = context_new(context);
	if (!new_context)
		return NULL;

	if ((opts & OPT_CHCON_USER) && context_user_set(new_context, user))
		goto error;
	if ((opts & OPT_CHCON_RANGE) && context_range_set(new_context, range))
		goto error;
	if ((opts & OPT_CHCON_ROLE) && context_role_set(new_context, role))
		goto error;
	if ((opts & OPT_CHCON_TYPE) && context_type_set(new_context, type))
		goto error;

	return new_context;
error:
	context_free (new_context);
	return NULL;
}

static int change_file_context(const char *file, unsigned long opts)
{
	security_context_t file_context = NULL;
	security_context_t context_string;
	context_t context;
	int errors = 0;
	int status = 0;

	if (opts & OPT_CHCON_NODEREFERENCE) {
		status = lgetfilecon(file, &file_context);
	} else {
		status = getfilecon(file, &file_context);
	}
	if (status < 0 && errno != ENODATA) {
		if ((opts & OPT_CHCON_QUIET) == 0)
			fprintf(stderr, "could not obtain security context: %s\n", file);
		return 1;
	}

	if (file_context == NULL && specified_context == NULL) {
		fprintf(stderr, "can't apply partial context to unlabeled file %s", file);
		return 1;
	}

	if (specified_context == NULL) {
		context = compute_context_from_mask(file_context, opts);
		if (!context) {
			fprintf(stderr, "couldn't compute security context from %s",
				file_context);
			return 1;
		}
	} else {
		context = context_new(specified_context);
		if (!context) {
			fprintf(stderr, "invalid context: %s", specified_context);
			return 1;
		}
	}

	context_string = context_str(context);
	if (file_context == NULL || strcmp(context_string, file_context)!=0) {
		int fail = 0;

		if (opts & OPT_CHCON_NODEREFERENCE) {
			fail = lsetfilecon (file, context_string);
		} else {
			fail = setfilecon (file, context_string);
		}
		if ((opts & OPT_CHCON_VERBOSE)
		    || ((opts & OPT_CHCON_CHANHES) && !fail)) {
			printf(!fail
			       ? "context of %s changed to %s\n"
			       : "failed to change context of %s to %s\n",
			       file, context_string);
		}
		if (fail) {
			errors = 1;
			if ((opts & OPT_CHCON_QUIET) == 0)
				fprintf(stderr, "failed to change context of %s to %s\n",
					file, context_string);
		}
	} else if (opts & OPT_CHCON_VERBOSE) {
		printf("context of %s retained as %s\n", file, context_string);
	}
	context_free(context);
	freecon(file_context);

	if (opts & OPT_CHCON_RECURSIVE) {
		struct stat file_stats;
		if (lstat(file, &file_stats) == 0
		    && S_ISDIR(file_stats.st_mode))
			errors |= change_dir_context(file, opts);
	}
	return errors;
}

static int change_dir_context(const char *dir_name, unsigned long opts)
{
	DIR *dir;
	struct dirent *dent;
	char buffer[PATH_MAX];
	int len, rc = 0;

	dir = opendir(dir_name);
	if (!dir) {
		if ((opts & OPT_CHCON_QUIET) == 0)
			fprintf(stderr, "failed to open directory %s\n", dir_name);
		return 1;
	}

	while ((dent = readdir(dir)) != NULL) {
		if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
			continue;
		len = snprintf(buffer, sizeof(buffer), "%s/%s",
			       dir_name, dent->d_name);
		if (len > sizeof(buffer)) {
			fprintf(stderr, "name too long: %s/%s\n",
				dir_name, dent->d_name);
			continue;
		}
		rc |= change_file_context(buffer, opts);
	}
	closedir(dir);

	return rc;
}

int chcon_main(int argc, char *argv[])
{
	char *fname;
	int i, errors = 0;
	unsigned long opts = chcon_parse_options(argc, argv);

	for (i=0; (fname = target_files[i]) != NULL; i++) {
		/* trancate last slashes */
		int fname_len = strlen(fname);
		while (fname_len > 1 && fname[fname_len - 1] == '/')
			fname_len--;
		fname[fname_len] = '\0';
		errors |= change_file_context(fname, opts);
	}

	return errors;
}
