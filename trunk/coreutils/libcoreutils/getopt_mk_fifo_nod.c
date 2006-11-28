/* vi: set sw=4 ts=4: */
/*
 * coreutils utility routine
 *
 * Copyright (C) 2003  Manuel Novoa III  <mjn3@codepoet.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 */

/* Nov 28, 2006      Yoshinori Sato <ysato@users.sourceforge.jp>
 *
 * Add -Z (SELinux) support.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "libbb.h"
#include "coreutils.h"
#ifdef CONFIG_SELINUX
#include <selinux/selinux.h>
#endif

mode_t getopt_mk_fifo_nod(int argc, char **argv)
{
	mode_t mode = 0666;
	char *smode = NULL;
#ifdef CONFIG_SELINUX
	int opt = 0;
	security_context_t scontext = NULL;

	opt = bb_getopt_ulflags(argc, argv, "m:Z:", &smode, &scontext);
#else
	bb_getopt_ulflags(argc, argv, "m:", &smode);
#endif
	if(smode) {
		if (bb_parse_mode(smode, &mode))
			umask(0);
	}
#ifdef CONFIG_SELINUX
	if(opt & 2) {
		if(!is_selinux_enabled()) {
			bb_error_msg_and_die ("Sorry, -Z can be used only on "
					      "a selinux-enabled kernel.\n" );
		}
		if (setfscreatecon(scontext)) {
			bb_error_msg_and_die ("Sorry, cannot set default context "
					      "to %s.\n", scontext);
		}
	}
#endif

	return mode;
}
