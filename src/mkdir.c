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

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#endif

#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#include KRB5_H

#ifdef HAVE_KEYUTILS_H
#include <keyutils.h>
#endif

#ifdef USE_SELINUX
#include <selinux/selinux.h>
#include <selinux/label.h>
#endif

#include "mkdir.h"
#include "userinfo.h"

#define PATH_SEPARATOR_S "/"
#define TMP_RUNTIME "/tmp"
#define TMP_PREFIX TMP_RUNTIME PATH_SEPARATOR_S
#define USER_RUNTIME "/run/user"
#define USER_PREFIX USER_RUNTIME PATH_SEPARATOR_S

static int
unlabeled_mkdir(const char *path, mode_t perms, uid_t uid, gid_t gid)
{
	int ret;
	ret = mkdir(path, perms);
	if (ret == 0) {
		ret = chown(path, uid, gid);
	}
	return ret;
}

#ifdef USE_SELINUX
static int
labeled_mkdir(const char *path, mode_t perms, uid_t uid, gid_t gid)
{
	struct selabel_handle *labels;
	security_context_t context, previous_context;
	int ret;

	if (!is_selinux_enabled()) {
		return unlabeled_mkdir(path, perms, uid, gid);
	}

	ret = -1;
	labels = selabel_open(SELABEL_CTX_FILE, NULL, 0);
	if (labels != NULL) {
		memset(&context, 0, sizeof(context));
		memset(&previous_context, 0, sizeof(previous_context));
		if (selabel_lookup(labels, &context, path, S_IFDIR) == 0) {
			if (getfscreatecon(&previous_context) == 0) {
				if (setfscreatecon(context) == 0) {
					ret = unlabeled_mkdir(path, perms, uid, gid);
					setfscreatecon(previous_context);
				}
			}
		} else {
			ret = unlabeled_mkdir(path, perms, uid, gid);
		}
		selabel_close(labels);
	}

	return ret;
}
#else
static int
labeled_mkdir(const char *path, mode_t perms, uid_t uid, gid_t gid)
{
	return unlabeled_mkdir(path, perms, uid, gid);
}
#endif

int
_pam_krb5_leading_mkdir(const char *path)
{
	char target[PATH_MAX], *p, *component;
	struct stat st;
	mode_t saved_umask;
	int ret;
	long id;
	uid_t uid = -1;
	gid_t gid = -1;

	/* Leading directories may be world-writable. */
	saved_umask = umask(0);
	/* Now, we're only doing this if we know about a given prefix. */
	ret = -1;
	if (strncmp(path, USER_PREFIX, strlen(USER_PREFIX)) == 0) {
		p = NULL;
		/* We "know" how to create /run/user/XXX .*/
		snprintf(target, sizeof(target), "%s", path);
		component = target + strlen(USER_PREFIX);
		component[strcspn(component, "/")] = '\0';
		if ((stat(target, &st) == 0) || (errno != ENOENT)) {
			/* Nothing to do. Reset the umask and return. */
			umask(saved_umask);
			return 0;
		}
		id = strtol(component, &p, 10);
		if ((id != LONG_MIN) && (id != LONG_MAX) &&
		    (p != NULL) && (p != component) && (*p == '\0')) {
			if (_pam_krb5_get_pw_ids(NULL, id, &uid, &gid) != 0) {
				/* Fail. */
				umask(saved_umask);
				return -1;
			}
		} else {
			if (strlen(component) > 0) {
				if (_pam_krb5_get_pw_ids(component, -1,
							 &uid, &gid) != 0) {
					/* Fail. */
					umask(saved_umask);
					return -1;
				}
			} else {
				/* Fail. */
				umask(saved_umask);
				return -1;
			}
		}
		ret = labeled_mkdir(target, S_IRWXU, uid, gid);
	}
	/* Okay, reset the umask. */
	umask(saved_umask);
	return ret;
}
