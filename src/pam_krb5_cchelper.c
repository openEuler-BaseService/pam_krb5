/*
 * Copyright 2012 Red Hat, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of the
 * GNU Lesser General Public License, in which case the provisions of the
 * LGPL are required INSTEAD OF the above restrictions.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "../config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include KRB5_H

#include "xstr.h"

/* A simple (hopefully) helper which creates a file using mkstemp() and a
 * supplied pattern, attempts to set the ownership of that file, stores
 * whatever it reads from stdin in that file, and then prints the file's name
 * on stdout.
 *
 * While all of this can be done directly by pam_krb5, we need to do it after
 * an exec() to have the file created with the proper context if we're running
 * in an SELinux environment, so the helper is used.  To simplify debugging and
 * maintenance, use of this helper is not conditionalized. */
int
main(int argc, const char **argv)
{
	krb5_context ctx = NULL;
	krb5_ccache ccache = NULL, tmp_ccache = NULL;
	krb5_principal client = NULL;
	char *ccname, *p, input[128 * 1024], pattern[PATH_MAX];
	long long uid, gid;
	gid_t current_gid;
	int fd, i, n_written;
	size_t n_input, n_output;

	/* We're not intended to be set*id! */
	if ((getuid() != geteuid()) || (getgid() != getegid())) {
		return 1;
	}

	/* One or three arguments.  No more, no less, else we bail. */
	if ((argc != 2) && (argc != 4)) {
		return 2;
	}

	/* We'll need a writable string for use as the template. */
	ccname = xstrdup(argv[1]);
	if ((ccname == NULL) || (strchr(ccname, ':') == NULL)) {
		return 3;
	}

	/* Parse the UID, if given. */
	if (argc > 2) {
#ifdef HAVE_STRTOLL
		uid = strtoll(argv[2], &p, 0);
#else
		uid = strtol(argv[2], &p, 0);
#endif
		if ((p == NULL) || (*p != '\0')) {
			return 5;
		}
	} else {
		uid = getuid();
	}

	/* Parse the GID, if given. */
	if (argc > 3) {
#ifdef HAVE_STRTOLL
		gid = strtoll(argv[3], &p, 0);
#else
		gid = strtol(argv[3], &p, 0);
#endif
		if ((p == NULL) || (*p != '\0')) {
			return 6;
		}
	} else {
		gid = getgid();
	}

	/* Attempt to drop supplemental groups and become the given user (if
	 * one was given).  Note that this may all fail if we're unprivileged,
	 * and that is expressly allowed. */
	current_gid = getgid();
	if (getuid() == 0) {
		setgroups(0, &current_gid);
	}
	if (getgid() != gid) {
		fd = setregid(gid, gid);
	}
	if (getuid() != uid) {
		fd = setreuid(uid, uid);
	}

	/* Read stdin. */
	n_input = 0;
	while (n_input < sizeof(input)) {
		i = read(STDIN_FILENO, input + n_input,
			 sizeof(input) - n_input);
		if (i < 0) {
			return 7;
		}
		n_input += i;
		if (i == 0) {
			close(STDIN_FILENO);
			break;
		}
	}
	if (n_input == sizeof(input)) {
		return 8;
	}

	i = krb5_init_context(&ctx);
	if (i != 0) {
		return i;
	}

	/* We have three modes.  First, zero-length input. */
	if (n_input == 0) {
		/* The first argument is a ccache to be removed. */
		i = krb5_cc_resolve(ctx, argv[1], &ccache);
		if (i != 0) {
			krb5_free_context(ctx);
			return i;
		}
		i = krb5_cc_destroy(ctx, ccache);
		krb5_free_context(ctx);
		return i;
	} else {
		/* Data is a ccache file's contents. */
		if ((strstr(ccname, "XXXXXX") != NULL) &&
		    (strncmp(ccname, "FILE:", 5) == 0)) {
			/* Just create the destination. */
			fd = mkstemp(ccname + 5);
			if (fd == -1) {
				fd = errno;
				krb5_free_context(ctx);
				return fd;
			}
			n_output = 0;
			while (n_output < n_input) {
				i = write(fd, input + n_output,
					  n_input - n_output);
				if (i < 0) {
					unlink(ccname + 5);
					krb5_free_context(ctx);
					return 9;
				}
				n_output += i;
			}
			close(fd);
			printf("%s\n", ccname);
			return 0;
		}
		/* Create a temporary file. */
		snprintf(pattern, sizeof(pattern), "FILE:%s/.pam_krb5_XXXXXX",
			 getenv("TMPDIR") ?: "/tmp");
		fd = mkstemp(pattern + 5);
		if (fd == -1) {
			krb5_free_context(ctx);
			return 9;
		}
		n_output = 0;
		while (n_output < n_input) {
			i = write(fd, input + n_output, n_input - n_output);
			if (i < 0) {
				krb5_free_context(ctx);
				unlink(pattern + 5);
				close(fd);
				return 10;
			}
			n_output += i;
		}
		close(fd);
		/* Open it as a ccache. */
		i = krb5_cc_resolve(ctx, pattern, &tmp_ccache);
		if (i != 0) {
			krb5_free_context(ctx);
			return i;
		}
		i = krb5_cc_get_principal(ctx, tmp_ccache, &client);
		if (i != 0) {
			krb5_cc_destroy(ctx, tmp_ccache);
			krb5_free_context(ctx);
			return i;
		}
		/* If the name is a pattern, instantiate it. */
		if (strstr(ccname, "XXXXXX") != NULL) {
			if (strncmp(ccname, "FILE:", 5) == 0) {
				fd = mkstemp(ccname + 5);
				if (fd == -1) {
					fd = errno;
					krb5_cc_destroy(ctx, tmp_ccache);
					krb5_free_context(ctx);
					return fd;
				}
				close(fd);
			} else {
				p = strchr(ccname, ':');
				mktemp(p + 1);
				if (strlen(p + 1) == 0) {
					return 11;
				}
				if (strncmp(ccname, "DIR:", 4) == 0) {
					if (mkdir(ccname + 4, S_IRWXU) != 0) {
						fd = errno;
						krb5_cc_destroy(ctx, tmp_ccache);
						krb5_free_context(ctx);
						return fd;
					}
				}
			}
		}
		/* Copy the credentials from the temporary ccache to the
		 * destination. */
		i = krb5_cc_resolve(ctx, ccname, &ccache);
		if (i != 0) {
			krb5_cc_destroy(ctx, tmp_ccache);
			krb5_free_context(ctx);
			return i;
		}
		i = krb5_cc_initialize(ctx, ccache, client);
		if (i != 0) {
			krb5_cc_destroy(ctx, ccache);
			krb5_cc_destroy(ctx, tmp_ccache);
			krb5_free_context(ctx);
			return i;
		}
		i = krb5_cc_copy_creds(ctx, tmp_ccache, ccache);
		if (i != 0) {
			krb5_cc_destroy(ctx, ccache);
			krb5_cc_destroy(ctx, tmp_ccache);
			krb5_free_context(ctx);
			return i;
		}
		krb5_cc_close(ctx, ccache);
		krb5_cc_destroy(ctx, tmp_ccache);
		krb5_free_context(ctx);
		printf("%s\n", ccname);
	}
	return 0;
}
