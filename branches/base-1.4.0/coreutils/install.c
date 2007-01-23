/*
 *  Copyright (C) 2003 by Glenn McGrath <bug1@iinet.net.au>
 *  Port to Busybox by Yuichi Nakamura <ynakam@hitachisoft.jp>
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *
 * TODO: -d option, need a way of recursively making directories and changing
 *           owner/group, will probably modify bb_make_directory(...)
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h> /* struct option */

#include "busybox.h"
#include "libcoreutils/coreutils.h"

#define INSTALL_OPT_CMD	1
#define INSTALL_OPT_DIRECTORY	2
#define INSTALL_OPT_PRESERVE_TIME	4
#define INSTALL_OPT_STRIP	8
#define INSTALL_OPT_GROUP  16
#define INSTALL_OPT_MODE  32
#define INSTALL_OPT_OWNER  64
#ifdef CONFIG_SELINUX
#define INSTALL_OPT_PRESERVE_SECURITY_CONTEXT  128
#define INSTALL_OPT_SET_SECURITY_CONTEXT  256
#endif

#if ENABLE_FEATURE_INSTALL_LONG_OPTIONS
static const struct option install_long_options[] = {
	{ "directory",	0,	NULL,	'd' },
	{ "preserve-timestamps",	0,	NULL,	'p' },
	{ "strip",	0,	NULL,	's' },
	{ "group",	0,	NULL,	'g' },
	{ "mode",	0,	NULL,	'm' },
	{ "owner",	0,	NULL,	'o' },
#ifdef CONFIG_SELINUX
	{ "preserve_context",	0,	NULL,	'P' },
	{ "context",	0,	NULL,	'Z' },
#endif
	{ 0,	0,	0,	0 }
};
#endif

#ifdef CONFIG_SELINUX
#include <selinux/selinux.h>
static int selinux_enabled = 0;
static int use_default_selinux_context = 1;

static void setdefaultfilecon(const char *path) {
	struct stat s;
	security_context_t scontext = NULL;
	
	if ( !selinux_enabled ){
		return;
	}	
	if ( lstat(path, &s) != 0){
		return;
	}

	if (matchpathcon(path, s.st_mode, &scontext) < 0){
		return;
	}
	if (strcmp(scontext, "<<none>>") == 0){
		freecon(scontext);
		return;
	}

	if (lsetfilecon(path, scontext) < 0) {
		if (errno != ENOTSUP) {
			bb_perror_msg("warning: failed to change context of %s to %s", path, scontext);
		}
	}

	freecon(scontext);
	return;
}

#endif

int install_main(int argc, char **argv)
{
	mode_t mode;
	uid_t uid;
	gid_t gid;
	char *gid_str = "-1";
	char *uid_str = "-1";
	char *mode_str = "0755";
	int copy_flags = FILEUTILS_DEREFERENCE | FILEUTILS_FORCE;
	int ret = EXIT_SUCCESS, flags, i, isdir;
#ifdef CONFIG_SELINUX
	char *context_str =NULL;
	selinux_enabled = (is_selinux_enabled()>0);
#endif

#if ENABLE_FEATURE_INSTALL_LONG_OPTIONS
	bb_applet_long_options = install_long_options;
#endif
	bb_opt_complementally = "?:s--d:d--s";
	/* -c exists for backwards compatibility, its needed */
#ifdef CONFIG_SELINUX
	flags = bb_getopt_ulflags(argc, argv, "cdpsg:m:o:PZ:", &gid_str, &mode_str, &uid_str,&context_str);	/* 'a' must be 2nd */
#else
	flags = bb_getopt_ulflags(argc, argv, "cdpsg:m:o:", &gid_str, &mode_str, &uid_str);	/* 'a' must be 2nd */
#endif


	/* preserve access and modification time, this is GNU behaviour, BSD only preserves modification time */
	if (flags & INSTALL_OPT_PRESERVE_TIME) {
		copy_flags |= FILEUTILS_PRESERVE_STATUS;
	}

#ifdef CONFIG_SELINUX
	if (flags & INSTALL_OPT_PRESERVE_SECURITY_CONTEXT) {	  
		if( !selinux_enabled ) {
			bb_error_msg("Warning:  ignoring --preserve_context (-P) "
		             "because the kernel is not selinux-enabled.\n" );		
		}else{
			copy_flags |= FILEUTILS_PRESERVE_SECURITY_CONTEXT;
			use_default_selinux_context = 0;
			if (flags & INSTALL_OPT_SET_SECURITY_CONTEXT){
				bb_error_msg_and_die("cannot force target context and preserve it\n");
			}
		}
	}
	if (flags & INSTALL_OPT_SET_SECURITY_CONTEXT){	
		if( !selinux_enabled ) {
			bb_error_msg("Warning:  ignoring --context (-Z) "
		             "because the kernel is not selinux-enabled.\n" );		
		}else{
			copy_flags |= FILEUTILS_SET_SECURITY_CONTEXT;
			use_default_selinux_context = 0;
			if (flags & INSTALL_OPT_PRESERVE_SECURITY_CONTEXT){			
				bb_error_msg_and_die("cannot force target context == '%s' and preserve it\n", context_str);
			}
			if (setfscreatecon(context_str)) {
				bb_error_msg_and_die("cannot setup default context == '%s'\n", context_str);
			}
		}
	}
#endif

	bb_parse_mode(mode_str, &mode);
	gid = get_ug_id(gid_str, bb_xgetgrnam);
	uid = get_ug_id(uid_str, bb_xgetpwnam);
	umask(0);

	/* Create directories
	 * dont use bb_make_directory() as it cant change uid or gid
	 * perhaps bb_make_directory() should be improved.
	 */
	if (flags & INSTALL_OPT_DIRECTORY) {
		for (argv += optind; *argv; argv++) {
			char *old_argv_ptr = *argv + 1;
			char *argv_ptr;
			do {
				argv_ptr = strchr(old_argv_ptr, '/');
				old_argv_ptr = argv_ptr;
				if (argv_ptr) {
					*argv_ptr = '\0';
					old_argv_ptr++;
				}
				if (mkdir(*argv, mode) == -1) {
					if (errno != EEXIST) {
						bb_perror_msg("coulnt create %s", *argv);
						ret = EXIT_FAILURE;
						break;
					}
				}
				else if (lchown(*argv, uid, gid) == -1) {
					bb_perror_msg("cannot change ownership of %s", *argv);
					ret = EXIT_FAILURE;
					break;
				}
				if (argv_ptr) {
					*argv_ptr = '/';
				}
			} while (old_argv_ptr);
		}
		return(ret);
	}

	{
		struct stat statbuf;
		isdir = lstat(argv[argc - 1], &statbuf)<0
					? 0 : S_ISDIR(statbuf.st_mode);
	}
	for (i = optind; i < argc - 1; i++) {
		char *dest;

		dest = argv[argc - 1];
		if (isdir) dest = concat_path_file(argv[argc - 1], basename(argv[i]));
		ret |= copy_file(argv[i], dest, copy_flags);

		/* Set the file mode */
		if (chmod(dest, mode) == -1) {
			bb_perror_msg("cannot change permissions of %s", dest);
			ret = EXIT_FAILURE;
		}
#ifdef CONFIG_SELINUX
		if (use_default_selinux_context)
			setdefaultfilecon(dest);
#endif
		/* Set the user and group id */
		if (lchown(dest, uid, gid) == -1) {
			bb_perror_msg("cannot change ownership of %s", dest);
			ret = EXIT_FAILURE;
		}
		if (flags & INSTALL_OPT_STRIP) {
			if (execlp("strip", "strip", dest, NULL) == -1) {
				bb_error_msg("strip failed");
				ret = EXIT_FAILURE;
			}
		}
		if(ENABLE_FEATURE_CLEAN_UP && isdir) free(dest);
	}

	return(ret);
}
