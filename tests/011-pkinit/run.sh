#!/bin/sh

. $testdir/testenv.sh

$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
$kadmin -q 'modprinc -pwexpire never '$test_principal 2> /dev/null > /dev/null

# Trust path only, should fail.
test_run -auth $test_principal $pam_krb5 $test_flags use_first_pass preauth_options=X509_anchors=FILE:$testdir/kdc/ca.crt

# Anonymous PKINIT.
echo ""
test_run -auth -session -run klist_i $test_principal $pam_krb5 $test_flags use_first_pass no_user_check preauth_options=X509_anchors=FILE:$testdir/kdc/ca.crt mappings="$test_principal WELLKNOWN/ANONYMOUS" debug

# User PKINIT.
echo ""
test_run -auth $test_principal $pam_krb5 $test_flags use_first_pass preauth_options=X509_anchors=FILE:$testdir/kdc/ca.crt,X509_user_identity=PKCS12:$testdir/kdc/${test_principal}.p12 pkinit_identity=PKCS12:$testdir/kdc/${test_principal}.p12
