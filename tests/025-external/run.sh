#!/bin/sh

. $testdir/testenv.sh

$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
$kadmin -q 'modprinc -pwexpire never '$test_principal 2> /dev/null > /dev/null

echo ""; echo "Obtaining creds:"
CCSAVE=${testdir}/kdc/krb5cc_save; export CCSAVE
test_run -auth -session $test_principal -run save_cc_file.sh $pam_krb5 $test_flags ccname_template=FILE:${testdir}/kdc/krb5cc_%U_XXXXXX -- foo

echo ""; echo "Using external creds:"
test_run -session $test_principal -setenv KRB5CCNAME=FILE:$CCSAVE -run grepenv.sh $pam_krb5 $test_flags external test_environment -- foo

rm -f $CCSAVE
find ${testdir}/kdc -name "krb5cc*" -print
