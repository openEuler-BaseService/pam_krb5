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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include KRB5_H

#ifdef HAVE_KEYUTILS_H
#include <keyutils.h>
#endif

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
	struct dirent **dents = NULL;
	long long uid, gid;
	gid_t current_gid;
	long id;
	int fd, i, j, n_written, c_flag = 0, d_flag = 0, u_flag = 0;
	size_t n_input, n_output;

	/* We're not intended to be set*id! */
	if ((getuid() != geteuid()) || (getgid() != getegid())) {
		return 1;
	}

	/* Two or four arguments.  No more, no less, else we bail. */
	if ((argc != 3) && (argc != 5)) {
		return 2;
	}

	/* Check what mode we're in. */
	if (strcmp(argv[1], "-c") == 0) {
		c_flag++;
	} else
	if (strcmp(argv[1], "-d") == 0) {
		d_flag++;
	} else
	if (strcmp(argv[1], "-u") == 0) {
		u_flag++;
	} else {
		return 3;
	}

	/* We'll need a writable string for use as the template. */
	ccname = xstrdup(argv[2]);
	if ((ccname == NULL) || (strchr(ccname, ':') == NULL)) {
		return 4;
	}

	/* Parse the UID, if given. */
	if (argc > 3) {
#ifdef HAVE_STRTOLL
		uid = strtoll(argv[3], &p, 0);
#else
		uid = strtol(argv[3], &p, 0);
#endif
		if ((p == NULL) || (*p != '\0')) {
			return 5;
		}
	} else {
		uid = getuid();
	}

	/* Parse the GID, if given. */
	if (argc > 4) {
#ifdef HAVE_STRTOLL
		gid = strtoll(argv[4], &p, 0);
#else
		gid = strtol(argv[4], &p, 0);
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

	/* We have three modes.  First, zero-length input should put us in to
	 * delete mode. */
	if (n_input == 0) {
		if (!d_flag) {
			return 9;
		}
		if (strstr(ccname, "XXXXXX") != NULL) {
			return 9;
		}
		/* The first argument is a ccache to be destroyed. */
		i = krb5_cc_resolve(ctx, ccname, &ccache);
		if (i != 0) {
			krb5_free_context(ctx);
			return i;
		}
		i = krb5_cc_destroy(ctx, ccache);
		/* Some ccache types require a bit more work. */
		if ((i == 0) && (strncmp(ccname, "DIR:", 4) == 0)) {
			if ((j = scandir(ccname + 4, &dents,
					 NULL, &alphasort)) > 0) {
				while (j > 0) {
					if ((strcmp(dents[j - 1]->d_name,
						    ".") != 0) &&
					    (strcmp(dents[j - 1]->d_name,
						    "..") != 0) &&
					    (snprintf(pattern, sizeof(pattern),
						      "%s/%s", ccname + 4,
						      dents[j - 1]->d_name) <
					     (int) sizeof(pattern))) {
						unlink(pattern);
					}
					j--;
				}
			}
			rmdir(ccname + 4);
			/* Nothing we can do if this fails. */
		} 
#ifdef HAVE_KEYUTILS_H
		if ((i == 0) && (strncmp(ccname, "KEYRING:", 8) == 0)) {
			id = keyctl_search(KEY_SPEC_SESSION_KEYRING,
					   "keyring", ccname + 8, 0);
			if (id != (long) -1) {
				id = keyctl_unlink(KEY_SPEC_SESSION_KEYRING,
						   id);
				/* Nothing we can do if this fails. */
			}
		}
#endif
		krb5_free_context(ctx);
		return i;
	}

	/* Non-zero-length input puts us in either create or update mode. */
	if (!c_flag && !u_flag) {
		return 9;
	}

	/* Simplest is if we're being asked to either create or update a FILE
	 * ccache. */
	if (strncmp(ccname, "FILE:", 5) == 0) {
		if (strstr(ccname, "XXXXXX") != NULL) {
			/* Check that we're in create mode, and create
			 * the file. */
			if (!c_flag) {
				return 9;
			}
			fd = mkstemp(ccname + 5);
		} else {
			/* Check that we're in update mode. */
			if (!u_flag) {
				return 9;
			}
			fd = open(ccname + 5, O_WRONLY | O_TRUNC);
		}
		if (fd == -1) {
			fd = errno;
			krb5_free_context(ctx);
			return fd;
		}
		/* Write the ccache contents to the file. */
		n_output = 0;
		while (n_output < n_input) {
			i = write(fd, input + n_output,
				  n_input - n_output);
			if (i < 0) {
				unlink(ccname + 5);
				krb5_free_context(ctx);
				return 10;
			}
			n_output += i;
		}
		close(fd);
		printf("%s\n", ccname);
		return 0;
	}

	/* Create a temporary file to deserialize the ccache. */
	snprintf(pattern, sizeof(pattern), "FILE:%s/pam_krb5_XXXXXX",
		 getenv("TMPDIR") ?: "/tmp");
	fd = mkstemp(pattern + 5);
	if (fd == -1) {
		krb5_free_context(ctx);
		return 11;
	}
	n_output = 0;
	while (n_output < n_input) {
		i = write(fd, input + n_output, n_input - n_output);
		if (i < 0) {
			krb5_free_context(ctx);
			unlink(pattern + 5);
			close(fd);
			return 12;
		}
		n_output += i;
	}
	close(fd);

	/* Open the file as a ccache. */
	i = krb5_cc_resolve(ctx, pattern, &tmp_ccache);
	if (i != 0) {
		unlink(pattern + 5);
		krb5_free_context(ctx);
		return i;
	}
	i = krb5_cc_get_principal(ctx, tmp_ccache, &client);
	if (i != 0) {
		krb5_cc_destroy(ctx, tmp_ccache);
		krb5_free_context(ctx);
		return i;
	}

	/* If the ccache is a directory, create one, if need be. */
	if (strncmp(ccname, "DIR:", 4) == 0) {
		if ((p = strstr(ccname, "XXXXXX")) != NULL) {
			/* Check that we're in create mode, and create
			 * a directory. */
			if (!c_flag) {
				krb5_cc_destroy(ctx, tmp_ccache);
				krb5_free_context(ctx);
				return 9;
			}
			do {
				/* Try to create a unique directory. */
				strcpy(ccname, argv[2]);
				mktemp(ccname + 4);
				if (strlen(ccname + 4) == 0) {
					i = EINVAL;
				} else {
					i = mkdir(ccname + 4, S_IRWXU);
				}
			} while ((i != 0) && (errno == EEXIST));
			if (i != 0) {
				krb5_cc_destroy(ctx, tmp_ccache);
				krb5_free_context(ctx);
				return i;
			}
		} else {
			/* Check that we're in update mode. */
			if (!u_flag) {
				krb5_cc_destroy(ctx, tmp_ccache);
				krb5_free_context(ctx);
				return 9;
			}
		}
#ifdef HAVE_KEYUTILS_H
	} else if (strncmp(ccname, "KEYRING:", 8) == 0) {
		if ((p = strstr(ccname, "XXXXXX")) != NULL) {
			/* Check that we're in create mode, and create
			 * a new keyring. */
			if (!c_flag) {
				krb5_cc_destroy(ctx, tmp_ccache);
				krb5_free_context(ctx);
				return 9;
			}
			do {
				/* Try to create a unique keyring name. */
				strcpy(ccname, argv[2]);
				mktemp(ccname + 8);
				if (strlen(ccname + 8) == 0) {
					i = EINVAL;
				} else {
					id = keyctl_search(KEY_SPEC_SESSION_KEYRING,
							   "keyring",
							   ccname + 8, 0);
					if (id == (long) -1) {
						id = add_key("keyring",
							     ccname + 8,
							     NULL, 0,
							     KEY_SPEC_SESSION_KEYRING);
						if (id == (long) -1) {
							break;
						}
					} else {
						errno = EEXIST;
						i = -1;
					}
				}
			} while ((i != 0) && (errno == EEXIST));
			if (i != 0) {
				krb5_cc_destroy(ctx, tmp_ccache);
				krb5_free_context(ctx);
				return i;
			}
		} else {
			/* Check that we're in update mode. */
			if (!u_flag) {
				krb5_cc_destroy(ctx, tmp_ccache);
				krb5_free_context(ctx);
				return 9;
			}
		}
#endif
	} else {
		/* Unsupported ccache type. */
		krb5_cc_destroy(ctx, tmp_ccache);
		krb5_free_context(ctx);
		return 13;
	}

	/* Copy the credentials from the temporary ccache to the
	 * ready-to-receive-them destination. */
	i = krb5_cc_resolve(ctx, ccname, &ccache);
	if (i != 0) {
		krb5_cc_destroy(ctx, tmp_ccache);
		krb5_free_context(ctx);
		return i;
	}
	i = krb5_cc_initialize(ctx, ccache, client);
	krb5_free_principal(ctx, client);
	if (i != 0) {
		krb5_cc_destroy(ctx, ccache);
		krb5_cc_destroy(ctx, tmp_ccache);
		krb5_free_context(ctx);
		return i;
	}
#ifdef HAVE_KRB5_CC_COPY_CREDS
	i = krb5_cc_copy_creds(ctx, tmp_ccache, ccache);
#else
	{
		krb5_creds creds;
		krb5_cc_cursor cursor;
		if ((i = krb5_cc_start_seq_get(ctx, tmp_ccache, &cursor)) != 0) {
			krb5_cc_destroy(ctx, ccache);
			krb5_cc_destroy(ctx, tmp_ccache);
			krb5_free_context(ctx);
			return i;
		}
		memset(&creds, 0, sizeof(creds));
		while ((i = krb5_cc_next_cred(ctx, tmp_ccache, &cursor, &creds)) == 0) {
			krb5_cc_store_cred(ctx, ccache, &creds);
			krb5_free_cred_contents(ctx, &creds);
			memset(&creds, 0, sizeof(creds));
		}
		krb5_cc_end_seq_get(ctx, tmp_ccache, &cursor);
	}
#endif
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
	return 0;
}
