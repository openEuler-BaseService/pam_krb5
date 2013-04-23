AM_CFLAGS = @KRB5_CFLAGS@
LIBS = @PAM_LIBS@ @KRB5_LIBS@ @KEYUTILS_LIBS@

testdir = `cd $(builddir); /bin/pwd`

noinst_PROGRAMS = pam_harness meanwhile klist_c klist_i
EXTRA_DIST = save_cc_file.sh grepenv.sh grepenvc.sh waitforkdc.sh waitforkpasswdd.sh
noinst_SCRIPTS = save_cc_file.sh grepenv.sh grepenvc.sh waitforkdc.sh waitforkpasswdd.sh

pam_harness_SOURCES = pam_harness.c
pam_harness_LDADD = -lpam -ldl
