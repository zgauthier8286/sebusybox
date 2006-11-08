#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <selinux/selinux.h>
#include <locale.h>			    /* for setlocale() */
#include <libintl.h>			    /* for gettext() */
#define _(msgid) gettext (msgid)
#ifndef PACKAGE
#define PACKAGE "policycoreutils"   /* the name of this package lang translation */
#endif

extern int load_policy_main(int argc, char **argv) 
{
	int fd, ret;
	struct stat sb;
	void *map;

	if (argc != 2) {
		fprintf(stderr, _("usage:  %s policyfile\n"), argv[0]);
		return 1;
	}

	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, _("Can't open '%s':  %s\n"),
			argv[1], strerror(errno));
		return 2;
	}

	if (fstat(fd, &sb) < 0) {
		fprintf(stderr, _("Can't stat '%s':  %s\n"),
			argv[1], strerror(errno));
		return 2;
	}

	map = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		fprintf(stderr, _("Can't map '%s':  %s\n"),
			argv[1], strerror(errno));
		return 2;
	}

	ret = security_load_policy(map, sb.st_size);
	if (ret < 0) {
		fprintf(stderr, _("%s:  security_load_policy failed\n"), argv[0]);
		return 3;
	}
	return EXIT_SUCCESS;
}
