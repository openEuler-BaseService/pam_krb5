#!/bin/sh

. $testdir/testenv.sh

$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
$kadmin -q 'modprinc -pwexpire never '$test_principal 2> /dev/null > /dev/null

echo ""; echo "Obtaining creds:"
CCSAVE=${testdir}/kdc/krb5cc_saved; export CCSAVE
test_run -auth -session $test_principal -run save_cc_file.sh $pam_krb5 $test_flags ccname_template=FILE:${testdir}/kdc/krb5cc_%U_XXXXXX -- foo

echo ""; echo "Using external creds:"
KRB5CCNAME=FILE:$CCSAVE; export KRB5CCNAME
test_run -session $test_principal -run klist_c $pam_krb5 -run klist_c $test_flags ccname_template=FILE:${testdir}/kdc/krb5cc_%U_XXXXXX external -- foo

kdestroy
find ${testdir}/kdc -name "krb5cc*" -print
