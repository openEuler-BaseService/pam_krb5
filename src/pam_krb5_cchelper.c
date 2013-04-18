/*
 * Copyright 2012,2013 Red Hat, Inc.
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
#include <limits.h>
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

#define PATH_SEPARATOR '/'

krb5_error_code
cc_resolve_and_initialize(krb5_context ctx, const char *ccname,
			  krb5_principal client, krb5_ccache *ccout)
{
	krb5_ccache ccache;
	krb5_error_code err;
#if defined(HAVE_KRB5_CC_SUPPORT_SWITCH) && \
    defined(HAVE_KRB5_CC_CACHE_MATCH) && \
    defined(HAVE_KRB5_CC_NEW_UNIQUE)
	krb5_cccol_cursor cursor;
	krb5_boolean make_primary;
	char *cctype, *hint, *defcc;
	const char *cdefcc;

	/* Set the default name to the already-not-a-template location that
	 * we're planning to use, in case we end up calling
	 * krb5_cc_new_unique() below. */
	cdefcc = krb5_cc_default_name(ctx);
	defcc = (cdefcc != NULL) ? strdup(cdefcc) : NULL;
	err = krb5_cc_set_default_name(ctx, ccname);

	/* Isolate the cctype. */
	cctype = strdup(ccname);
	hint = strchr(cctype, ':');
	if (hint != NULL) {
		*hint++ = '\0';
	}

	/* If the type supports switching... */
	if (krb5_cc_support_switch(ctx, cctype)) {
		/* check if there are any ccaches in there yet */
		make_primary = FALSE;
		if (krb5_cccol_cursor_new(ctx, &cursor) == 0) {
			ccache = NULL;
			if ((krb5_cccol_cursor_next(ctx, cursor,
						    &ccache) == 0) &&
			    (ccache != NULL)) {
				make_primary = FALSE;
			} else {
				make_primary = TRUE;
			}
			krb5_cccol_cursor_free(ctx, &cursor);
		}
		/* check if we already have a ccache for this client. */
		ccache = NULL;
		err = krb5_cc_cache_match(ctx, client, &ccache);
		if (err != 0) {
			if (err == KRB5_CC_NOTFOUND) {
				/* We don't have one -> create a new one. */
				err = krb5_cc_new_unique(ctx, cctype, hint,
							 &ccache);
			} else {
				/* Some other error -> just start over. */
				err = krb5_cc_resolve(ctx, ccname, &ccache);
			}
		}
		/* make this the primary ccache if there wasn't already one */
		if ((ccache != NULL) && make_primary) {
			krb5_cc_switch(ctx, ccache);
		}
	} else {
		/* Just resolve the name for overwriting later. */
		err = krb5_cc_resolve(ctx, ccname, &ccache);
	}
	krb5_cc_set_default_name(ctx, defcc);
#else
	err = krb5_cc_resolve(ctx, ccname, &ccache);
#endif
	*ccout = NULL;
	if (err == 0) {
		err = krb5_cc_initialize(ctx, ccache, client);
		if (err == 0) {
			*ccout = ccache;
			return 0;
		}
		krb5_cc_close(ctx, ccache);
	}
	return err;
}

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
	char *ccname, *ccparent, *p, input[128 * 1024], pattern[PATH_MAX];
	struct dirent **dents = NULL;
	struct stat st;
	long long uid, gid;
	gid_t current_gid;
	long id;
	int fd, i, j, c_flag = 0, d_flag = 0, u_flag = 0;
	size_t n_input, n_output;

	/* Get this out of the way. */
	umask(S_IRGRP | S_IWGRP | S_IXGRP | S_IROTH | S_IWOTH | S_IXOTH);

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
			return 5;
		}
	} else {
		gid = getgid();
	}

	/* Attempt to drop supplemental groups and become the given user (if
	 * one was given).  Note that this may all fail if we're unprivileged,
	 * and that is expressly allowed. */
	current_gid = getgid();
	if (getuid() == 0) {
		if (setgroups(0, &current_gid) == -1) {
			if (geteuid() == 0) {
				return 6;
			}
		}
	}
	if (getgid() != gid) {
		if (setregid(gid, gid) == -1) {
			if (geteuid() == 0) {
				return 6;
			}
		}
	}
	if (getuid() != uid) {
		if (setreuid(uid, uid) == -1) {
			if (geteuid() == 0) {
				return 6;
			}
		}
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
		if ((i == 0) &&
		    (strncmp(ccname, "DIR:", 4) == 0) &&
		    (ccname[4] != ':')) {
			if ((j = scandir(ccname + 4, &dents,
					 NULL, &alphasort)) > 0) {
				while (j > 0) {
					if (((strcmp(dents[j - 1]->d_name,
						     "primary") == 0) ||
					     (strncmp(dents[j - 1]->d_name,
						      "tkt", 3) == 0)) &&
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
		krb5_free_context(ctx);
		return 9;
	}

	/* Simplest is if we're being asked to either create or update a FILE
	 * ccache. */
	if (strncmp(ccname, "FILE:", 5) == 0) {
		if (strstr(ccname, "XXXXXX") != NULL) {
			/* Check that we're in create mode, and create
			 * the file. */
			if (!c_flag) {
				krb5_free_context(ctx);
				return 9;
			}
			fd = mkstemp(ccname + 5);
		} else {
			/* Check that we're either in update mode, or that we
			 * already own the file, or the parent directory if the
			 * file doesn't exist. */
			if (!u_flag) {
				ccparent = strdup(ccname + 5);
				if (ccparent == NULL) {
					return 9;
				}
				for (i = strlen(ccparent) - 1;
				     i > 0;
				     i--) {
					if (ccparent[i] == PATH_SEPARATOR) {
						ccparent[i] = '\0';
					} else {
						break;
					}
					break;
				}
				for (i = strlen(ccparent) - 1;
				     i > 0;
				     i--) {
					if (ccparent[i] != PATH_SEPARATOR) {
						ccparent[i] = '\0';
					} else {
						break;
					}
				}
				for (i = strlen(ccparent) - 1;
				     i > 0;
				     i--) {
					if (ccparent[i] == PATH_SEPARATOR) {
						ccparent[i] = '\0';
					} else {
						break;
					}
					break;
				}
				if (stat(ccname + 5, &st) == 0) {
					/* Check that we own the file. */
					if ((st.st_uid != uid) ||
					    (st.st_gid != gid) ||
					    ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0) ||
					    !S_ISREG(st.st_mode)) {
						return 9;
					}
				} else if ((errno == ENOENT) &&
					   (stat(ccparent, &st) == 0)) {
					/* Check that we own the parent
					 * directory. */
					if ((st.st_uid != uid) ||
					    (st.st_gid != gid) ||
					    !S_ISDIR(st.st_mode)) {
						return 9;
					}
				}
			}
			fd = open(ccname + 5, O_CREAT | O_WRONLY | O_TRUNC,
				  S_IRUSR | S_IWUSR);
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
				ccparent = strdup(ccname + 4);
				if (ccparent == NULL) {
					return 9;
				}
				for (i = strlen(ccparent) - 1;
				     i > 0;
				     i--) {
					if (ccparent[i] == PATH_SEPARATOR) {
						ccparent[i] = '\0';
					} else {
						break;
					}
					break;
				}
				for (i = strlen(ccparent) - 1;
				     i > 0;
				     i--) {
					if (ccparent[i] != PATH_SEPARATOR) {
						ccparent[i] = '\0';
					} else {
						break;
					}
				}
				for (i = strlen(ccparent) - 1;
				     i > 0;
				     i--) {
					if (ccparent[i] == PATH_SEPARATOR) {
						ccparent[i] = '\0';
					} else {
						break;
					}
					break;
				}
				if (stat(ccname + 4, &st) == 0) {
					/* Check that we own the directory. */
					if ((st.st_uid != uid) ||
					    (st.st_gid != gid) ||
					    ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0) ||
					    !S_ISDIR(st.st_mode)) {
						return 9;
					}
				} else if ((errno == ENOENT) &&
					   (stat(ccparent, &st) == 0)) {
					/* Check that we own the parent
					 * directory. */
					if ((st.st_uid != uid) ||
					    (st.st_gid != gid) ||
					    !S_ISDIR(st.st_mode)) {
						return 9;
					}
					i = mkdir(ccname + 4, S_IRWXU);
					if (i != 0) {
						return i;
					}
				} else {
					krb5_cc_destroy(ctx, tmp_ccache);
					krb5_free_context(ctx);
					return 9;
				}
			}
		}
	} else if (strncmp(ccname, "SCC:", 4) == 0) {
		if ((p = strstr(ccname, "XXXXXX")) != NULL) {
			/* Check that we're in create mode, and create an empty
			 * file which sqlite has no qualms about overwriting. */
			if (!c_flag) {
				krb5_cc_destroy(ctx, tmp_ccache);
				krb5_free_context(ctx);
				return 9;
			}
			fd = mkstemp(ccname + 4);
			if (fd == -1) {
				krb5_cc_destroy(ctx, tmp_ccache);
				krb5_free_context(ctx);
				return i;
			}
			close(fd);
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
				/* Create the keyring if it doesn't already exist. */
				id = keyctl_search(KEY_SPEC_SESSION_KEYRING,
						   "keyring",
						   ccname + 8, 0);
				if (id == (long) -1) {
					id = add_key("keyring",
						     ccname + 8,
						     NULL, 0,
						     KEY_SPEC_SESSION_KEYRING);
					if (id == (long) -1) {
						i = errno;
						krb5_cc_destroy(ctx, tmp_ccache);
						krb5_free_context(ctx);
						return i;
					}
				}
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
	ccache = NULL;
	i = cc_resolve_and_initialize(ctx, ccname, client, &ccache);
	krb5_free_principal(ctx, client);
	if (i != 0) {
		if (ccache != NULL) {
			krb5_cc_destroy(ctx, ccache);
		}
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
