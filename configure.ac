AC_INIT(configure.ac)
AM_INIT_AUTOMAKE(pam_krb5,`rpm -q --specfile ${srcdir:-.}/pam_krb5.spec --qf '%{version}\n' | head -n1`)
AC_PROG_CC
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_PATH_PROG(KRB5_CONFIG,krb5-config,,[$PATH:/usr/kerberos/bin:/usr/krb5/bin])
AC_PATH_PROG(KRB4_CONFIG,krb4-config,,[$PATH:/usr/kerberos/bin:/usr/krb4/bin])
if $KRB5_CONFIG --libs krb4 > /dev/null 2> /dev/null; then
	AC_MSG_RESULT(Using krb4 provided with krb5.)
	KRB4_CONFIG="$KRB5_CONFIG krb4"
fi

KRB5_BINDIR=`dirname $KRB5_CONFIG`
AC_SUBST(KRB5_BINDIR)

AC_CHECK_LIB(resolv,main)
KRB5_CFLAGS=`$KRB5_CONFIG --cflags krb5`
KRB4_CFLAGS=`$KRB4_CONFIG --cflags krb4`
KRB5_LIBS=`$KRB5_CONFIG --libs krb5`
KRB4_LIBS=`$KRB4_CONFIG --libs krb4`

AC_MSG_CHECKING(for KRB5_CFLAGS)
AC_SUBST(KRB5_CFLAGS)
AC_MSG_RESULT($KRB5_CFLAGS)

AC_MSG_CHECKING(for KRB4_CFLAGS)
AC_SUBST(KRB4_CFLAGS)
AC_MSG_RESULT($KRB4_CFLAGS)

AC_MSG_CHECKING(for KRB5_LIBS)
AC_SUBST(KRB5_LIBS)
AC_MSG_RESULT($KRB5_LIBS)

AC_MSG_CHECKING(for KRB4_LIBS)
AC_SUBST(KRB4_LIBS)
AC_MSG_RESULT($KRB4_LIBS)

AC_CHECK_HEADERS(security/pam_appl.h)
AC_CHECK_HEADERS(security/pam_modules.h)
AC_CHECK_FUNCS(getpwnam_r)
AC_CHECK_FUNC(crypt,,[AC_CHECK_LIB(crypt,crypt)])

# We need GNU sed for this to work, but okay.
KRB5_CPPFLAGS=`echo $KRB5_CFLAGS | sed 's,-[^I][^[:space:]]*,,g'`
KRB4_CPPFLAGS=`echo $KRB4_CFLAGS | sed 's,-[^I][^[:space:]]*,,g'`

CPPFLAGS="$CPPFLAGS $KRB5_CPPFLAGS $KRB4_CPPFLAGS"
CFLAGS="$CFLAGS $KRB5_CFLAGS $KRB4_CFLAGS"
LIBS="$LIBS $KRB5_LIBS $KRB4_LIBS"

AC_CHECK_HEADERS(krb5.h)
if test x$ac_cv_header_krb5_h != xyes ; then
	AC_MSG_ERROR(you must have Kerberos 5 development files to build $PACKAGE)
fi
AC_CHECK_HEADER(krb.h,,[AC_CHECK_HEADER(kerberosIV/krb.h)])
AC_CHECK_HEADER(kafs.h,,[AC_CHECK_HEADER(krbafs.h)])
if test x$ac_cv_header_kafs_h = xyes ; then
	AC_CHECK_FUNC(k_hasafs,,[AC_CHECK_LIB(kafs,k_hasafs,,,$LIBS)])
else
	if test x$ac_cv_header_krbafs_h = xyes ; then
		AC_CHECK_FUNC(k_hasafs,,[AC_CHECK_LIB(krbafs,k_hasafs,,,$LIBS)])
	fi
fi
if test x$ac_cv_lib_krbafs_k_hasafs = xyes ; then
	AC_DEFINE(KRB4_AFS_H,[<krbafs.h>],[Define to the name of your krbafs.h header.])
	AC_DEFINE(USE_AFS,1,[Define to use afslog() and friends.])
else
	if test x$ac_cv_lib_kafs_k_hasafs = xyes ; then
		AC_DEFINE(KRB4_AFS_H,[<kafs.h>],[Define to the name of your krbafs.h header.])
		AC_DEFINE(USE_AFS,1,[Define to use afslog() and friends.])
	else
		AC_MSG_WARN([no AFS functionality available])
	fi
fi
if test x$ac_cv_header_krb_h = xyes ; then
	AC_DEFINE(USE_KRB4,1,[Define if you have Kerberos IV as well.])
	AC_DEFINE(KRB4_DES_H,[<des.h>],[Define to the name of your Kerberos IV des.h header.])
	AC_DEFINE(KRB4_KRB_H,[<krb.h>],[Define to the name of your Kerberos IV krb.h header.])
	AC_CHECK_HEADER(krb_err.h,[AC_DEFINE(KRB4_KRB_ERR_H,[<krb_err.h>],[Define to the name of your Kerberos IV krb_err.h header, if you have one.])])
else
	if test x$ac_cv_header_kerberosIV_krb_h = xyes ; then
		AC_DEFINE(USE_KRB4,1,[Define if you have Kerberos IV as well.])
		AC_DEFINE(KRB4_DES_H,[<kerberosIV/des.h>],[Define to the name of your Kerberos IV des.h header.])
		AC_DEFINE(KRB4_KRB_H,[<kerberosIV/krb.h>],[Define to the name of your Kerberos IV krb.h header.])
		AC_CHECK_HEADER(kerberosIV/krb_err.h,[AC_DEFINE(KRB4_KRB_ERR_H,[<kerberosIV/krb_err.h>],[Define to the name of your Kerberos IV krb_err.h header, if you have one.])])
	else
		AC_MSG_WARN([no Kerberos IV functionality available])
	fi
fi

AC_CHECK_FUNCS(initialize_krb5_error_table initialize_krb4_error_table initialize_krb_error_table krb_life_to_time krb5_init_secure_context krb5_free_unparsed_name krb5_free_default_realm krb5_set_principal_realm krb_in_tkt in_tkt krb_save_credentials save_credentials)
headers='
#include <stdio.h>
#if HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif
#if HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif
#if STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# if HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif
#if HAVE_STRING_H
# if !STDC_HEADERS && HAVE_MEMORY_H
#  include <memory.h>
# endif
# include <string.h>
#endif
#if HAVE_STRINGS_H
# include <strings.h>
#endif
#if HAVE_INTTYPES_H
# include <inttypes.h>
#else
# if HAVE_STDINT_H
#  include <stdint.h>
# endif
#endif
#if HAVE_UNISTD_H
# include <unistd.h>
#endif
#include <krb5.h>'
AC_CHECK_DECL(error_message,
	      [AC_DEFINE(HAVE_ERROR_MESSAGE_DECL,1,[Define if your krb5.h declares the error_message() function.])],,[$headers])
AC_CHECK_HEADERS(com_err.h et/com_err.h)

AC_CHECK_DECL(krb5_os_localaddr,
	      [AC_DEFINE(HAVE_KRB5_OS_LOCALADDR,1,[Define if your krb5.h declares the krb5_os_localaddr() function.])],,[$headers])
AC_CHECK_DECL(krb5_os_hostaddr,
	      [AC_DEFINE(HAVE_KRB5_OS_HOSTADDR,1,[Define if your krb5.h declares the krb5_os_hostaddr() function.])],,[$headers])
AC_CHECK_DECL(krb5_copy_addr,
	      [AC_DEFINE(HAVE_KRB5_COPY_ADDR,1,[Define if your krb5.h declares the krb5_copy_addr() function.])],,[$headers])
AC_CHECK_DECL(krb5_get_all_client_addrs,
	      [AC_DEFINE(HAVE_KRB5_GET_ALL_CLIENT_ADDRS,1,[Define if your krb5.h declares the krb5_get_all_client_addrs() function.])],,[$headers])

AC_CHECK_TYPES(krb5_const_realm,,,[$headers])
AC_CHECK_MEMBERS(krb5_creds.keyblock,,,[$headers])
AC_CHECK_MEMBERS(krb5_creds.session,,,[$headers])
AC_CHECK_MEMBERS(krb5_keyblock.enctype,,,[$headers])
AC_CHECK_MEMBERS(krb5_keyblock.keytype,,,[$headers])

AC_CHECK_FUNC(krb524_convert_creds_kdc,,[AC_CHECK_LIB(krb524,krb524_convert_creds_kdc,,[AC_CHECK_LIB(54,krb524_convert_creds_kdc)])])
AC_CHECK_FUNCS(krb5_524_convert_creds)
if test x$ac_cv_function_krb5_524_convert_creds = xyes ; then
	AC_DEFINE(HAVE_KRB5_524_CONVERT_CREDS,1,[Define if you have the krb5_524_convert_creds function.])
else
	if test x$ac_cv_lib_krb524_krb5_524_convert_creds_kdc = xyes ; then
		AC_DEFINE(HAVE_KRB524_CONVERT_CREDS_KDC,1,[Define if you have the krb524_convert_creds_kdc function.])
		LIBS="$LIBS -lkrb524"
	else
		if test x$ac_cv_lib_54_krb5_524_convert_creds_kdc = xyes ; then
			AC_DEFINE(HAVE_KRB524_CONVERT_CREDS_KDC,1,[Define if you have the krb524_convert_creds_kdc function.])
			LIBS="$LIBS -l54"
		fi
	fi
fi

AC_ARG_ENABLE(default-realm,AC_HELP_STRING([--enable-default-realm=REALM],[last-ditch fallback realm (default is EXAMPLE.COM)]),default_realm=$enableval,default_realm=EXAMPLE.COM)
AC_DEFINE_UNQUOTED(DEFAULT_REALM,"$default_realm",[Define to the realm name which will be used if no realm is given as a parameter and none is given in krb5.conf.])
AC_MSG_RESULT([Using "$default_realm" as the default realm])
AC_ARG_ENABLE(default-ccache-dir,AC_HELP_STRING([--enable-default-ccache-dir=DIRECTORY],[default directory in which ccache files will be stored (default is /tmp)]),default_ccache_dir=$enableval,default_ccache_dir=/tmp)
AC_DEFINE_UNQUOTED(DEFAULT_CCACHE_DIR,"$default_ccache_dir",[Define to the name of the directory in which ccache files will be stored by default.])
AC_MSG_RESULT([Using "$default_ccache_dir" to store ccache files])

PAM_KRB5_APPNAME=pam
AC_DEFINE_UNQUOTED(PAM_KRB5_APPNAME,"$PAM_KRB5_APPNAME",[Define to the application name, which defines which appdefaults section will be expected to hold this module's configuration in krb5.conf.])
AC_SUBST(PAM_KRB5_APPNAME)

AC_DEFINE(PAM_KRB5_MAYBE_CONST,[const],[Define to the proper qualifier (either const or nothing) for your PAM implementation.])
AC_DEFINE(PASSWORD_CHANGE_PRINCIPAL,["kadmin/changepw"],[Define to the principal name of the password-changing service for any given realm.])

if test x$GCC = xyes ; then
	CFLAGS="$CFLAGS -Wall -Wimplicit -Wunused -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations -Wcast-align"
	AC_ARG_ENABLE(Werror,AC_HELP_STRING([--enable-Werror],[enable -Werror as a compile flag (default is no)]),[CFLAGS="$CFLAGS -Werror"])
fi

AH_VERBATIM([PAM_KRB5_GNUC_PRINTF_DEFINED],
[/* Add attribute tags to help spot format specifier problems. */
 #ifdef __GNUC__
 #define PAM_KRB5_GNUC_PRINTF(__x,__y) __attribute__((format(printf,__x,__y)))
 #else
 #define PAM_KRB5_GNUC_PRINTF(__x,__y)
 #endif
])

TESTDIR=`cd ${ac_top_builddir:-.}; /bin/pwd`/tests
TESTHOST=`hostname`
AC_SUBST(TESTDIR)
AC_SUBST(TESTHOST)
AC_SUBST(default_ccache_dir)

AC_CONFIG_HEADER(config.h)
AC_OUTPUT([
Makefile
src/Makefile
src/pam_krb5.5
src/pam_krb5.8
pam.d/Makefile
tests/Makefile
tests/config/Makefile
tests/config/krb5.conf
tests/config/kdc.conf
tests/config/krb.conf
tests/kdc/Makefile
tests/tools/Makefile
tests/tools/klist_t
tests/tools/klist_f
tests/tools/klist_c
tests/tools/klist_a
tests/tools/klist_4
])