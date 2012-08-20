AM_CFLAGS = @KRB5_CFLAGS@
LIBS = @PAM_LIBS@ @KRB5_LIBS@ @KEYUTILS_LIBS@

testdir = `cd $(builddir); /bin/pwd`

noinst_PROGRAMS = pam_harness meanwhile klist_a klist_a0 klist_f klist_t klist_c
klist_a_LDADD = \
	../../src/libpam_krb5.la \
	../../src/logstdio.lo \
	../../src/noitems.lo \
	$(LIBS)
klist_a0_LDADD = \
	../../src/libpam_krb5.la \
	../../src/logstdio.lo \
	../../src/noitems.lo \
	$(LIBS)

pam_harness_SOURCES = pam_harness.c
pam_harness_LDADD = -lpam -ldl
