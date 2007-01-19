/* 
 * setfiles
 *  Based on policycoreutils 1.33.10
 *  Port to busybox by Yuichi Nakamura <ynakam@hitachisoft.jp>
 */

#include "busybox.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include <string.h>

#define xstreq(x, y) !strcmp(x, y)

#include <err.h>

#include <getopt.h>
#include <sys/types.h>
#include <unistd.h>
#include <selinux/selinux.h>
#include <selinux/context.h>

#define SECON_CONF_PROG_NAME "secon"	/* default program name */
#define VERSION "1.33.10"
#define OPTS_FROM_ARG      0
#define OPTS_FROM_FILE     1
#define OPTS_FROM_LINK     2
#define OPTS_FROM_STDIN    3
#define OPTS_FROM_CUR      4
#define OPTS_FROM_CUREXE   5
#define OPTS_FROM_CURFS    6
#define OPTS_FROM_CURKEY   7
#define OPTS_FROM_PROC     8
#define OPTS_FROM_PROCEXE  9
#define OPTS_FROM_PROCFS   10
#define OPTS_FROM_PROCKEY  11

struct {
	unsigned int disp_user:1;
	unsigned int disp_role:1;
	unsigned int disp_type:1;
	unsigned int disp_sen:1;
	unsigned int disp_clr:1;
	unsigned int disp_mlsr:1;

	unsigned int disp_raw:1;

	unsigned int disp_prompt:1;	/* no return, use : to sep */

	unsigned int from_type:8;	/* 16 bits, uses 4 bits */

	union {
		pid_t pid;
		const char *file;
		const char *link;
		const char *arg;
	} f;
} opts[1] = { {
		FALSE, FALSE, FALSE, FALSE, FALSE, FALSE,
		    FALSE, FALSE, OPTS_FROM_ARG, {
0}}};

static const char *opt_program_name(const char *argv0, const char *def)
{
	if (argv0) {
		if ((def = strrchr(argv0, '/')))
			++def;
		else
			def = argv0;

		/* hack for libtool */
		if ((strlen(def) > strlen("lt-"))
		    && !memcmp("lt-", def, strlen("lt-")))
			def += 3;
	}

	return (def);
}

static int disp_num(void)
{
	int num = 0;

	num += opts->disp_user;
	num += opts->disp_role;
	num += opts->disp_type;
	num += opts->disp_sen;
	num += opts->disp_clr;
	num += opts->disp_mlsr;

	return (num);
}

static int disp_none(void)
{
	return (!disp_num());
}

static int disp_multi(void)
{
	return (disp_num() > 1);
}

#ifdef CONFIG_FEATURE_SECON_LONG_OPTIONS
struct option long_options[] = {
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'V'},
	
	{"prompt", no_argument, NULL, 'P'},
	
	{"user", no_argument, NULL, 'u'},
	{"role", no_argument, NULL, 'r'},
	{"type", no_argument, NULL, 't'},
	{"level", no_argument, NULL, 'l'},	/* compat. */
	{"sensitivity", no_argument, NULL, 's'},
	{"range", no_argument, NULL, 'm'},
	{"clearance", no_argument, NULL, 'c'},
	{"mls-range", no_argument, NULL, 'm'},
	
	{"raw", no_argument, NULL, 'R'},
	
	{"current", no_argument, NULL, 1},
	{"self", no_argument, NULL, 1},
       	{"current-exec", no_argument, NULL, 2},
	{"self-exec", no_argument, NULL, 2},
	{"current-fs", no_argument, NULL, 3},
	{"self-fs", no_argument, NULL, 3},
	{"current-key", no_argument, NULL,4},
	{"self-key", no_argument, NULL, 4},	
	{"parent", no_argument, NULL,5},
	{"parent-exec", no_argument, NULL, 6},
	{"parent-fs", no_argument, NULL, 7},
	{"parent-key", no_argument, NULL, 8},
	
	{"file", required_argument, NULL, 'f'},
	{"link", required_argument, NULL, 'L'},
	{"pid", required_argument, NULL, 'p'},
	{"pid-exec", required_argument, NULL, 9},
	{"pid-fs", required_argument, NULL, 0xa},
	{"pid-key", required_argument, NULL, 0xb},

	{NULL, 0, NULL, 0}
};
#endif

#define OPTS_h    (1<<0)
#define OPTS_V    (1<<1)
#define OPTS_P    (1<<2)
#define OPTS_u    (1<<3)
#define OPTS_r    (1<<4)
#define OPTS_t    (1<<5)
#define OPTS_l    (1<<6)
#define OPTS_s    (1<<7)
#define OPTS_m    (1<<8)
#define OPTS_c    (1<<9)
#define OPTS_R    (1<<10)
#define OPTS_f    (1<<11)
#define OPTS_L    (1<<12)
#define OPTS_p    (1<<13)
#define OPTS_CURRENT (1<<14)
#define OPTS_CURRENT_EXEC (1<<15)
#define OPTS_CURRENT_FS (1<<16)
#define OPTS_CURRENT_KEY (1<<17)
#define OPTS_PARENT (1<<18)
#define OPTS_PARENT_EXEC (1<<19)
#define OPTS_PARENT_FS (1<<20)
#define OPTS_PARENT_KEY (1<<21)
#define OPTS_PID_EXEC (1<<22)
#define OPTS_PID_FS (1<<23)
#define OPTS_PID_KEY (1<<24)


static void cmd_line(int argc, char *argv[])
{
	const char *program_name = NULL;
	int done = FALSE;
	unsigned long option;
	char *pid_str = NULL;
	char *pid_exec_str = NULL;
	char *pid_fs_str = NULL;
	char *pid_key_str = NULL;
	program_name = opt_program_name(argv[0], SECON_CONF_PROG_NAME);

#ifdef CONFIG_FEATURE_SECON_LONG_OPTIONS
	bb_applet_long_options = long_options;
#endif
	option = bb_getopt_ulflags(argc, argv, "hVPurtlsmcRf:L:p:\x1\x2\x3\x4\x5\x6\x7\x8\x9:\xa:\xb:",
				   &(opts->f.file),
				   &(opts->f.link),
				   &(pid_str),
				   &(pid_exec_str),
				   &(pid_fs_str),
				   &(pid_key_str));
	
	if(option & BB_GETOPT_ERROR)
		bb_show_usage();

	if(option & OPTS_h)
		bb_show_usage();

	if(option & OPTS_V){
		fprintf(stdout,
				" %s: based on policy coreutils %s.\n", program_name, VERSION);
		exit(EXIT_SUCCESS);
	}

	if(option & OPTS_u){
		done = TRUE;
		opts->disp_user = !opts->disp_user;
	}
	
	if(option & OPTS_r){
		done = TRUE;
		opts->disp_role = !opts->disp_role;
		
	}
	
	if(option & OPTS_t){
		done = TRUE;
		opts->disp_type = !opts->disp_type;
	}

	if(option & OPTS_l){
		done = TRUE;
		opts->disp_sen = !opts->disp_sen;
	}

	if(option & OPTS_s){
		done = TRUE;
		opts->disp_sen = !opts->disp_sen;
	}

	if(option & OPTS_c){
		done = TRUE;
		opts->disp_clr = !opts->disp_clr;
	}

	if(option & OPTS_m){
		done = TRUE;
		opts->disp_mlsr = !opts->disp_mlsr;
	}

	if(option & OPTS_P){
		opts->disp_prompt = !opts->disp_prompt;
	}

	if(option & OPTS_R){
		opts->disp_raw = !opts->disp_raw;
	}

	if(option & OPTS_CURRENT){
		opts->from_type = OPTS_FROM_CUR;
	}

	if(option & OPTS_CURRENT_EXEC){
		opts->from_type = OPTS_FROM_CUREXE;
	}

	if(option & OPTS_CURRENT_FS){
		opts->from_type = OPTS_FROM_CURFS;
	}

	if(option & OPTS_CURRENT_KEY){
		opts->from_type = OPTS_FROM_CURKEY;
	}

	if(option & OPTS_PARENT){
		opts->from_type = OPTS_FROM_PROC;
		opts->f.pid = getppid();
	}

	if(option & OPTS_PARENT_EXEC){
		opts->from_type = OPTS_FROM_PROCEXE;
		opts->f.pid = getppid();
	}

	if(option & OPTS_PARENT_FS){
		opts->from_type = OPTS_FROM_PROCFS;
		opts->f.pid = getppid();
	}

	if(option & OPTS_PARENT_KEY){
		opts->from_type = OPTS_FROM_PROCKEY;
		opts->f.pid = getppid();
	}

	if(option & OPTS_f){
		opts->from_type = OPTS_FROM_FILE;
		opts->f.file = optarg;
	}

	if(option & OPTS_L){
		opts->from_type = OPTS_FROM_LINK;
	}
	
	if(option & OPTS_p){
			opts->from_type = OPTS_FROM_PROC;
			opts->f.pid = atoi(pid_str);
	}

	if(option & OPTS_PID_EXEC){
			opts->from_type = OPTS_FROM_PROCEXE;
			opts->f.pid = atoi(pid_exec_str);
	}

	if(option & OPTS_PID_FS){
		opts->from_type = OPTS_FROM_PROCFS;
		opts->f.pid = atoi(pid_fs_str);
	}

	if(option & OPTS_PID_KEY){
		opts->from_type = OPTS_FROM_PROCKEY;
		opts->f.pid = atoi(pid_key_str);
	}

	if (!done) {		/* defualt, if nothing specified */
		opts->disp_user = TRUE;
		opts->disp_role = TRUE;
		opts->disp_type = TRUE;
		if (!opts->disp_prompt) {	/* when displaying prompt, just output "normal" by default */
			opts->disp_sen = TRUE;
			opts->disp_clr = TRUE;
		}
		opts->disp_mlsr = TRUE;
	}

	if (disp_none())
		err(EXIT_FAILURE, " Nothing to display");

	argc -= optind;
	argv += optind;

	if (!argc && (opts->from_type == OPTS_FROM_ARG)
	    && !isatty(STDIN_FILENO))
		opts->from_type = OPTS_FROM_STDIN;
	if (!argc && (opts->from_type == OPTS_FROM_ARG))
		opts->from_type = OPTS_FROM_CUR;

	if (opts->from_type == OPTS_FROM_ARG) {
		opts->f.arg = argv[0];

		if (xstreq(argv[0], "-"))
			opts->from_type = OPTS_FROM_STDIN;
	} else if (!is_selinux_enabled())
		errx(EXIT_FAILURE, "SELinux is not enabled");
}

static int my_getXcon_raw(pid_t pid, security_context_t * con, const char *val)
{
	char buf[4096];
	FILE *fp = NULL;
	const char *ptr = NULL;

	snprintf(buf, sizeof(buf), "%s/%ld/attr/%s", "/proc", (long int)pid,
		 val);

	if (!(fp = fopen(buf, "rb")))
		return (-1);

	ptr = fgets(buf, sizeof(buf), fp);

	fclose(fp);

	*con = NULL;
	if (ptr) {		/* return *con = NULL, when proc file is empty */
		char *tmp = strchr(ptr, '\n');

		if (tmp)
			*tmp = 0;

		if (*ptr && !(*con = strdup(ptr)))
			return (-1);
	}

	return (0);
}

static int my_getpidexeccon_raw(pid_t pid, security_context_t * con)
{
	return (my_getXcon_raw(pid, con, "exec"));
}
static int my_getpidfscreatecon_raw(pid_t pid, security_context_t * con)
{
	return (my_getXcon_raw(pid, con, "fscreate"));
}
static int my_getpidkeycreatecon_raw(pid_t pid, security_context_t * con)
{
	return (my_getXcon_raw(pid, con, "keycreate"));
}

static security_context_t get_scon(void)
{
	static char dummy_NIL[1] = "";
	security_context_t con = NULL;
	int ret = -1;
	int raw = TRUE;

	switch (opts->from_type) {
	case OPTS_FROM_ARG:
		if (!(con = strdup(opts->f.arg)))
			err(EXIT_FAILURE,
			    " Couldn't allocate security context");
		raw = !opts->disp_raw;	/* always do conversion */
		break;

	case OPTS_FROM_STDIN:
		{
			char buf[4096] = "";
			char *ptr = buf;

			while (!*ptr) {
				if (!(ptr = fgets(buf, sizeof(buf), stdin)))
					err(EXIT_FAILURE,
					    " Couldn't read security context");

				ptr += strspn(ptr, " \n\t");
				ptr[strcspn(ptr, " \n\t")] = 0;
			}

			if (!(con = strdup(ptr)))
				err(EXIT_FAILURE,
				    " Couldn't allocate security context");

			raw = !opts->disp_raw;	/* always do conversion */
			break;
		}

	case OPTS_FROM_CUR:
		ret = getcon_raw(&con);

		if (ret == -1)
			err(EXIT_FAILURE,
			    " Couldn't get current security context");
		break;
	case OPTS_FROM_CUREXE:
		ret = getexeccon_raw(&con);

		if (ret == -1)
			err(EXIT_FAILURE,
			    " Couldn't get current exec security context");

		if (!con)
			con = strdup(dummy_NIL);
		break;
	case OPTS_FROM_CURFS:
		ret = getfscreatecon_raw(&con);

		if (ret == -1)
			err(EXIT_FAILURE,
			    " Couldn't get current fs security context");

		if (!con)
			con = strdup(dummy_NIL);
		break;
	case OPTS_FROM_CURKEY:
		ret = getkeycreatecon_raw(&con);

		if (ret == -1)
			err(EXIT_FAILURE,
			    " Couldn't get current key security context");

		if (!con)
			con = strdup(dummy_NIL);
		break;

	case OPTS_FROM_PROC:
		ret = getpidcon_raw(opts->f.pid, &con);

		if (ret == -1)
			err(EXIT_FAILURE,
			    " Couldn't get security context for pid %lu",
			    (unsigned long)opts->f.pid);
		break;
	case OPTS_FROM_PROCEXE:
		ret = my_getpidexeccon_raw(opts->f.pid, &con);

		if (ret == -1)
			err(EXIT_FAILURE,
			    " Couldn't get security context for pid %lu",
			    (unsigned long)opts->f.pid);

		if (!con)
			con = strdup(dummy_NIL);
		break;
	case OPTS_FROM_PROCFS:
		ret = my_getpidfscreatecon_raw(opts->f.pid, &con);

		if (ret == -1)
			err(EXIT_FAILURE,
			    " Couldn't get security context for pid %lu",
			    (unsigned long)opts->f.pid);

		if (!con)
			con = strdup(dummy_NIL);
		/* disabled -- override with normal context ...
		   {
		   opts->from_type = OPTS_FROM_PROC;
		   return (get_scon());
		   } */
		break;
	case OPTS_FROM_PROCKEY:
		ret = my_getpidkeycreatecon_raw(opts->f.pid, &con);

		if (ret == -1)
			err(EXIT_FAILURE,
			    " Couldn't get security context for pid %lu",
			    (unsigned long)opts->f.pid);

		if (!con)
			con = strdup(dummy_NIL);
		break;

	case OPTS_FROM_FILE:
		ret = getfilecon_raw(opts->f.file, &con);

		if (ret == -1)
			err(EXIT_FAILURE,
			    " Couldn't get security context for file %s",
			    opts->f.file);
		break;

	case OPTS_FROM_LINK:
		ret = lgetfilecon_raw(opts->f.link, &con);

		if (ret == -1)
			err(EXIT_FAILURE,
			    " Couldn't get security context for symlink %s",
			    opts->f.link);
		break;

	default:
		assert(FALSE);
	}

	if (opts->disp_raw != raw) {
		security_context_t ncon = NULL;

		if (opts->disp_raw)
			selinux_trans_to_raw_context(con, &ncon);
		else
			selinux_raw_to_trans_context(con, &ncon);

		freecon(con);
		con = ncon;
	}

	return (con);
}

static void disp__con_val(const char *name, const char *val)
{
	static int done = FALSE;

	assert(name);

	if (!val)
		val = "";	/* targeted has no "level" etc.,
				   any errors should happen at context_new() time */

	if (opts->disp_prompt) {
		if (xstreq("mls-range", name) && !*val)
			return;	/* skip, mls-range if it's empty */

		fprintf(stdout, "%s%s", done ? ":" : "", val);
	} else if (disp_multi())
		fprintf(stdout, "%s: %s\n", name, val);
	else
		fprintf(stdout, "%s\n", val);

	done = TRUE;
}

static void disp_con(security_context_t scon)
{
	context_t con = NULL;

	if (!*scon) {		/* --self-exec and --self-fs etc. */
		if (opts->disp_user)
			disp__con_val("user", NULL);
		if (opts->disp_role)
			disp__con_val("role", NULL);
		if (opts->disp_type)
			disp__con_val("type", NULL);
		if (opts->disp_sen)
			disp__con_val("sensitivity", NULL);
		if (opts->disp_clr)
			disp__con_val("clearance", NULL);
		if (opts->disp_mlsr)
			disp__con_val("mls-range", NULL);
		return;
	}

	if (!(con = context_new(scon)))
		errx(EXIT_FAILURE, "Couldn't create context from: %s", scon);

	if (opts->disp_user)
		disp__con_val("user", context_user_get(con));
	if (opts->disp_role)
		disp__con_val("role", context_role_get(con));
	if (opts->disp_type)
		disp__con_val("type", context_type_get(con));
	if (opts->disp_sen) {
		const char *val = NULL;
		char *tmp = NULL;

		val = context_range_get(con);
		if (!val)
			val = "";	/* targeted has no "level" etc.,
					   any errors should happen at context_new() time */

		tmp = strdup(val);
		if (!tmp)
			errx(EXIT_FAILURE, "Couldn't create context from: %s",
			     scon);
		if (strchr(tmp, '-'))
			*strchr(tmp, '-') = 0;

		disp__con_val("sensitivity", tmp);

		free(tmp);
	}
	if (opts->disp_clr) {
		const char *val = NULL;
		char *tmp = NULL;

		val = context_range_get(con);
		if (!val)
			val = "";	/* targeted has no "level" etc.,
					   any errors should happen at context_new() time */

		tmp = strdup(val);
		if (!tmp)
			errx(EXIT_FAILURE, "Couldn't create context from: %s",
			     scon);
		if (strchr(tmp, '-'))
			disp__con_val("clearance", strchr(tmp, '-') + 1);
		else
			disp__con_val("clearance", tmp);

		free(tmp);
	}

	if (opts->disp_mlsr)
		disp__con_val("mls-range", context_range_get(con));

	context_free(con);
}



int secon_main(int argc, char *argv[])
{
	security_context_t scon = NULL;

	cmd_line(argc, argv);

	scon = get_scon();

	disp_con(scon);

	freecon(scon);

	exit(EXIT_SUCCESS);
}
