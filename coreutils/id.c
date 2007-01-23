/* vi: set sw=4 ts=4: */
/*
 * Mini id implementation for busybox
 *
 * Copyright (C) 2000 by Randolph Chung <tausq@debian.org>
 *
 * -Z option support: by Yuichi Nakamura <ynakam@hitachisoft.jp>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

/* BB_AUDIT SUSv3 _NOT_ compliant -- option -G is not currently supported. */
/* Hacked by Tito Ragusa (C) 2004 to handle usernames of whatever length and to
 * be more similar to GNU id.
 */

#include "busybox.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

#ifdef CONFIG_SELINUX
#include <selinux/selinux.h>          /* for is_selinux_enabled() */
#endif

#define PRINT_REAL        1
#define NAME_NOT_NUMBER   2
#define JUST_USER         4
#define JUST_GROUP        8
#ifdef CONFIG_SELINUX
#define JUST_CONTEXT    16
#endif

static short printf_full(unsigned int id, const char *arg, const char prefix)
{
	const char *fmt = "%cid=%u";
	short status = EXIT_FAILURE;

	if (arg) {
		fmt = "%cid=%u(%s)";
		status = EXIT_SUCCESS;
	}
	printf(fmt, prefix, id, arg);
	return status;
}

int id_main(int argc, char **argv)
{
	struct passwd *p;
	uid_t uid;
	gid_t gid;
	unsigned long flags;
	short status;
#ifdef CONFIG_SELINUX
	security_context_t scontext;
#endif

	/* Don't allow -n -r -nr -ug -rug -nug -rnug */
	/* Don't allow more than one username */
	bb_opt_complementally = "?1:?:u--g:g--u:r?ug:n?ug";
	flags = bb_getopt_ulflags(argc, argv, "rnugZ");

	/* This values could be overwritten later */
	uid = geteuid();
	gid = getegid();
	if (flags & PRINT_REAL) {
		uid = getuid();
		gid = getgid();
	}

	if(argv[optind]) {
		p=getpwnam(argv[optind]);
		/* bb_xgetpwnam is needed because it exits on failure */
		uid = bb_xgetpwnam(argv[optind]);
		gid = p->pw_gid;
		/* in this case PRINT_REAL is the same */
	}

#ifdef CONFIG_SELINUX
	if(flags & (JUST_GROUP | JUST_USER | JUST_CONTEXT )) {
#else
	if(flags & (JUST_GROUP | JUST_USER )) {
#endif
		/* JUST_GROUP and JUST_USER are mutually exclusive */
		if(flags & NAME_NOT_NUMBER) {
			/* bb_getpwuid and bb_getgrgid exit on failure so puts cannot segfault */
			puts((flags & JUST_USER) ? bb_getpwuid(NULL, uid, -1 ) : bb_getgrgid(NULL, gid, -1 ));
		} else {
			if (flags & JUST_USER){
				bb_printf("%u\n",uid);
			}
			if (flags & JUST_GROUP){
				bb_printf("%u\n",gid);
			}
		}

#ifdef CONFIG_SELINUX
		if(flags & JUST_CONTEXT){
			if( !is_selinux_enabled() ) {
				bb_error_msg_and_die("Sorry, --context (-Z) can be used only on "
									 "a selinux-enabled kernel.\n" );			
			}
			if (argc - optind == 1){
				bb_error_msg("cannot print security context when user specified");					
				bb_fflush_stdout_and_exit(EXIT_FAILURE);
			}

			if (getcon(&scontext)){
				bb_error_msg("can't get process context");		
				bb_fflush_stdout_and_exit(EXIT_FAILURE);
			}
			bb_printf("%s\n", scontext);
		}
#endif
		/* exit */
		bb_fflush_stdout_and_exit(EXIT_SUCCESS);
	}

	/* Print full info like GNU id */
	/* bb_getpwuid doesn't exit on failure here */
	status=printf_full(uid, bb_getpwuid(NULL, uid, 0), 'u');
	putchar(' ');
	/* bb_getgrgid doesn't exit on failure here */
	status|=printf_full(gid, bb_getgrgid(NULL, gid, 0), 'g');
	

#ifdef CONFIG_SELINUX
	if ( is_selinux_enabled() ) {
			security_context_t mysid;
			char context[80];
			int len = sizeof(context);

			getcon(&mysid);
			context[0] = '\0';
			if (mysid) {
					len = strlen(mysid)+1;
					safe_strncpy(context, mysid, len);
					freecon(mysid);
			}else{
					safe_strncpy(context, "unknown",8);
			}
		bb_printf(" context=%s", context);
	}
#endif

	putchar('\n');
	bb_fflush_stdout_and_exit(status);
}
