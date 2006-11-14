/* selinux/runcon.c
 *
 *
 *
 */
#include "busybox.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <error.h>
#include <errno.h>
#include <selinux/selinux.h>
#include <selinux/context.h>
#include <selinux/flask.h>
#include <selinux/av_permissions.h>


#ifdef CONFIG_FEATURE_RUNCON_LONG_OPTIONS
static struct option runcon_options[] = {
	{"user",	1, NULL, 'u' },
	{"role",	1, NULL, 'r' },
	{"type",	1, NULL, 't' },
	{"range",	1, NULL, 'l' },
	{"compute",	0, NULL, 'c' },
	{"help",	0, NULL, 'h' },
	{"version",	0, NULL, 'v' },
	{NULL,		0, NULL, 0}
};
#endif

struct runcon_environ {
	char *cmdname;
	char **cmdargs;
	char *user;
	char *role;
	char *type;
	char *range;
	char *context;
	int compute_trans;
};

#define OPTS_ROLE	(1<<0)	/* r */
#define OPTS_TYPE	(1<<1)	/* t */
#define OPTS_USER	(1<<2)	/* u */
#define OPTS_RANGE	(1<<3)	/* l */
#define OPTS_COMPUTE	(1<<4)	/* c */
#define OPTS_HELP	(1<<5)	/* h */
#define OPTS_VERSION	(1<<6)	/* v */

static int runcon_parse_options(int argc, char *argv[], struct runcon_environ *env)
{
	unsigned long opts;

#ifdef CONFIG_FEATURE_RUNCON_LONG_OPTIONS
	bb_applet_long_options = runcon_options;
#endif
	opts = bb_getopt_ulflags(argc, argv, "r:t:u:l:chv",
				 env->role,
				 env->type,
				 env->user,
				 env->range);

	env->compute_trans = (opts & OPTS_COMPUTE);
	if (opts & OPTS_VERSION) {
		fprintf(stderr, "-v, --version option is not supported yet\n");
		return 1;
	}
	if (opts & OPTS_HELP) {
		bb_show_usage();
		return 1;
	}

	if (!(env->user || env->role || env->type || env->range || env->compute_trans)) {
		if (optind >= argc) {
			fprintf(stderr, "must specify -c, -t, -u, -l, -r, or context\n");
			bb_show_usage();
		}
		env->context = argv[optind++];
	}

	if (optind >= argc) {
		fprintf(stderr, "no command found\n");
		bb_show_usage();
	}

	env->cmdname = argv[optind];
	env->cmdargs = argv + optind;

	return 0;
}

static context_t runcon_compute_new_context(struct runcon_environ *env)
{
	context_t con;
	security_context_t cur_context;

	if (getcon(&cur_context) != 0) {
		fprintf(stderr, "could not get current context.\n");
		return NULL;
	}
	if (env->compute_trans) {
		security_context_t file_context, new_context;

		if (getfilecon(env->cmdname, &file_context) != 0) {
			fprintf(stderr, "unable to retrieve attributes of '%s'.\n", env->cmdname);
			return NULL;
		}
		if (security_compute_create(cur_context, file_context,
					    SECCLASS_PROCESS, &new_context) != 0) {
			fprintf(stderr, "unable to compute a new context.\n");
			return NULL;
		}
		cur_context = new_context;
	}

	con = context_new(cur_context);
	if (!con) {
		fprintf(stderr, "'%s' is not a valid context.\n", cur_context);
		return NULL;
	}
	if (env->user && context_user_set(con, env->user)) {
		fprintf(stderr, "failed to set new user '%s'\n", env->user);
		return NULL;
	}
	if (env->type && context_type_set(con, env->type)) {
		fprintf(stderr, "failed to set new type '%s'\n", env->type);
		return NULL;
	}
	if (env->range && context_range_set(con, env->range)) {
		fprintf(stderr, "failed to set new range '%s'\n", env->range);
		return NULL;
	}
	if (env->role && context_role_set(con, env->role)) {
		fprintf(stderr, "failed to set new role '%s'", env->role);
		return NULL;
	}

	return con;
}

int runcon_main(int argc, char *argv[])
{
	struct runcon_environ env;
	context_t con;
	int rc;

	if (is_selinux_enabled() != 1) {
		fprintf(stderr, "runcon may be used only on a SELinux kernel.\n");
		return 1;
	}

	memset(&env, 0, sizeof(env));
	rc = runcon_parse_options(argc, argv, &env);
	if (rc != 0)
		return rc;

	if (env.context) {
		con = context_new(env.context);
		if (!con) {
			fprintf(stderr,"'%s' is not a valid context\n", env.context);
			return 1;
		}
	} else {
		con = runcon_compute_new_context(&env);
		if (!con)
			return 1;
	}

	if (security_check_context(context_str(con)) != 0) {
		fprintf(stderr, "'%s' is not a valid context\n", context_str(con));
		return 1;
	}

	if (setexeccon(context_str(con)) != 0) {
		fprintf(stderr, "unable to set up security context '%s'\n", context_str(con));
		return 1;
	}

	execvp(env.cmdname, env.cmdargs);
	/* should not be here */
	fprintf(stderr, "execvp() error (errno=%d, %s)\n", errno, strerror(errno));
	return 1;
}
