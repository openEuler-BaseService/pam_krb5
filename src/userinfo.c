#include "../config.h"

#include <sys/types.h>
#include <errno.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_SECURITY_PAM_MODULES_H
#include <security/pam_modules.h>
#endif

#include <krb5.h>
#ifdef USE_KRB4
#include KRB4_DES_H
#include KRB4_KRB_H
#ifdef KRB4_KRB_ERR_H
#include KRB4_KRB_ERR_H
#endif
#endif

#include "log.h"
#include "userinfo.h"
#include "v5.h"

#ident "$Id$"

#ifdef HAVE_GETPWNAM_R
#define CHUNK_SIZE 128
/* Convert a name to a UID/GID pair. */
static int
_get_pw_nam(const char *name, uid_t *uid, gid_t *gid)
{
	struct passwd passwd, *pwd;
	char *buffer;
	int size, i;

	size = CHUNK_SIZE;
	do {
		/* Allocate a temporary buffer to hold the string data. */
		buffer = malloc(size);
		if (buffer == NULL) {
			return 1;
		}
		memset(buffer, '\0', size);

		/* Give it a shot. */
		pwd = NULL;
		i = getpwnam_r(name, &passwd, buffer, size, &pwd);
		free(buffer);

		/* If we got 0 back, AND pwd now points to the passwd
		 * structure, then we succeeded. */
		if ((i == 0) && (pwd == &passwd)) {
			break;
		}

		/* We need to use more space if we got ERANGE back, and errno
		 * is ERANGE, so bail on any other condition. */
		if ((i != ERANGE) || (errno != ERANGE)) {
			return 1;
		}

		/* Increase the size of the buffer. */
		size += CHUNK_SIZE;
	} while (size > 0);

	/* If we exited successfully, then pull out the UID/GID. */
	if ((i == 0) && (pwd != NULL)) {
		*uid = pwd->pw_uid;
		*gid = pwd->pw_gid;
		return 0;
	}

	/* Failed. */
	return 1;
}
#else
static int
_get_pw_nam(const char *name, uid_t *uid, gid_t *gid)
{
	struct passwd *pwd;
	pwd = getpwnam(name);
	if (pwd != NULL) {
		*uid = pwd->pw_uid;
		*gid = pwd->pw_gid;
		return 0;
	}
	return 1;
}
#endif

struct _pam_krb5_user_info *
_pam_krb5_user_info_init(krb5_context ctx, const char *name, const char *realm,
			 int check_user)
{
	struct _pam_krb5_user_info *ret = NULL;
	char local_name[LINE_MAX];
	int i;

	ret = malloc(sizeof(struct _pam_krb5_user_info));
	if (ret == NULL) {
		return NULL;
	}
	memset(ret, 0, sizeof(struct _pam_krb5_user_info));

	/* Parse the user's name into a principal name. */
	if (krb5_parse_name(ctx, name, &ret->principal_name) != 0) {
		warn("error parsing principal name '%s'", name);
		free(ret);
		return NULL;
	}

	/* Override the realm part of the principal's name. */
	if (v5_set_principal_realm(ctx, &ret->principal_name, realm) != 0) {
		warn("internal error setting realm name");
		krb5_free_principal(ctx, ret->principal_name);
		free(ret);
		return NULL;
	}

	if (check_user) {
		/* Convert the principal name back into a local user's name. */
		memset(local_name, '\0', sizeof(local_name));
		i = krb5_aname_to_localname(ctx, ret->principal_name,
					    sizeof(local_name) - 1,
					    local_name);
		if (i != 0) {
			warn("error converting principal name to user name "
			     "(check auth_to_local and auth_to_local_names "
			     "settings in krb5.conf): %s",
			     v5_error_message(i));
			krb5_free_principal(ctx, ret->principal_name);
			free(ret);
			return NULL;
		}
		/* Look up the user's UID/GID. */
		if (_get_pw_nam(local_name, &ret->uid, &ret->gid) != 0) {
			warn("error resolving user name to uid/gid pair");
			krb5_free_principal(ctx, ret->principal_name);
			free(ret);
			return NULL;
		}
	} else {
		/* Set things to the current UID/GID. */
		ret->uid = getuid();
		ret->gid = getgid();
	}

	/* Convert the principal back to a full principal name string. */
	if (krb5_unparse_name(ctx, ret->principal_name,
			      &ret->unparsed_name) != 0) {
		warn("error converting principal name to string");
		krb5_free_principal(ctx, ret->principal_name);
		free(ret);
		return NULL;
	}

	return ret;
}

void
_pam_krb5_user_info_free(krb5_context ctx, struct _pam_krb5_user_info *info)
{
	krb5_free_principal(ctx, info->principal_name);
	v5_free_unparsed_name(ctx, info->unparsed_name);
	free(info);
}
