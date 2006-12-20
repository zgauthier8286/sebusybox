/* matchpathcon  -  get the default security context for the specified
 *                  path from the file contexts configuration.
 *                  based on libselinux-1.32
 * Port to busybox: KaiGai Kohei <kaigai@kaigai.gr.jp>
 *
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <selinux/selinux.h>
#include "busybox.h"

int printmatchpathcon(char *path, int header)
{
	char *buf;
	int rc = matchpathcon(path, 0, &buf);
	if (rc < 0) {
		fprintf(stderr, "matchpathcon(%s) failed: %s\n", path,
			strerror(errno));
		return 1;
	}
	if (header)
		printf("%s\t%s\n", path, buf);
	else
		printf("%s\n", buf);

	freecon(buf);
	return 0;
}

#define MATCHPATHCON_OPT_NOT_PRINT	(1<<0)	/* -n */
#define MATCHPATHCON_OPT_NOT_TRANS	(1<<1)	/* -N */
#define MATCHPATHCON_OPT_FCONTEXT	(1<<2)	/* -f */
#define MATCHPATHCON_OPT_PREFIX		(1<<3)	/* -p */
#define MATCHPATHCON_OPT_VERIFY		(1<<4)	/* -V */

int matchpathcon_main(int argc, char **argv)
{
	int i;
	int header = 1;
	int verify = 0;
	int notrans = 0;
	int error = 0;
	unsigned long opts;
	char *fcontext, *prefix;

	if (argc < 2)
		bb_show_usage();

	opts = bb_getopt_ulflags(argc, argv, "nNf:p:V", &fcontext, &prefix);
	if (opts & BB_GETOPT_ERROR)
		bb_show_usage();
	if (opts & MATCHPATHCON_OPT_NOT_PRINT)
		header = 0;
	if (opts & MATCHPATHCON_OPT_NOT_TRANS) {
		notrans = 1;
		set_matchpathcon_flags(MATCHPATHCON_NOTRANS);
	}
	if ((opts & MATCHPATHCON_OPT_FCONTEXT) && (opts & MATCHPATHCON_OPT_PREFIX))
		bb_error_msg_and_die("-f and -p are exclusive");

	if (opts & MATCHPATHCON_OPT_FCONTEXT) {
		if (matchpathcon_init(fcontext))
			bb_error_msg_and_die("Error while processing %s: %s",
					     fcontext, errno ? strerror(errno) : "invalid");
	}
	if (opts & MATCHPATHCON_OPT_PREFIX) {
		if (matchpathcon_init_prefix(NULL, prefix))
			bb_error_msg_and_die("Error while processing %s:  %s",
					     prefix, errno ? strerror(errno) : "invalid");
	}
	if (opts & MATCHPATHCON_OPT_VERIFY)
		verify = 1;

	for (i = optind; i < argc; i++) {
		if (verify) {
			if (selinux_file_context_verify(argv[i], 0)) {
				printf("%s verified.\n", argv[i]);
			} else {
				security_context_t con;
				int rc;
				if (notrans)
					rc = lgetfilecon_raw(argv[i], &con);
				else
					rc = lgetfilecon(argv[i], &con);

				if (rc >= 0) {
					printf("%s has context %s, should be ",
					       argv[i], con);
					error += printmatchpathcon(argv[i], 0);
					freecon(con);
				} else {
					printf
					    ("actual context unknown: %s, should be ",
					     strerror(errno));
					error += printmatchpathcon(argv[i], 0);
				}
			}
		} else {
			error += printmatchpathcon(argv[i], header);
		}
	}
	matchpathcon_fini();
	return error;
}
