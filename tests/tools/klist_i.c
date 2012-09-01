#include "../../config.h"
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <krb5.h>
int
main(int argc, char **argv)
{
	krb5_context ctx;
	krb5_ccache ccache;
	krb5_principal principal;
	char *unparsed;
	krb5_error_code ret;

	ctx = NULL;
	ret = krb5_init_context(&ctx);
	if ((ret = krb5_init_context(&ctx)) != 0) {
		printf("Error initializing Kerberos.\n");
		return ret;
	}
	if ((ret = krb5_cc_default(ctx, &ccache)) != 0) {
		printf("Error resolving ccache.\n");
		return ret;
	}
	if ((ret = krb5_cc_get_principal(ctx, ccache, &principal)) != 0) {
		printf("Error reading default principal.\n");
		return ret;
	}
	if ((ret = krb5_unparse_name(ctx, principal, &unparsed)) != 0) {
		printf("Error unparsing default principal.\n");
		return ret;
	}
	printf("%s\n", unparsed);
	krb5_cc_close(ctx, ccache);
	krb5_free_context(ctx);
	return 0;
}
