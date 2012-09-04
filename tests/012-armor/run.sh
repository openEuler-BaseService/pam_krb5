#!/bin/sh

. $testdir/testenv.sh

$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
$kadmin -q 'modprinc -pwexpire never '$test_principal 2> /dev/null > /dev/null

# Anonymous PKINIT armor.
echo ""
test_run -auth -session -run grepenvc.sh -authtok foo $test_principal $pam_krb5 $test_flags use_first_pass preauth_options=X509_anchors=FILE:$testdir/kdc/ca.crt test_environment armor armor_strategy=pkinit

# Use a keytab.
echo ""
test_run -auth -session -run grepenvc.sh -authtok foo $test_principal $pam_krb5 $test_flags use_first_pass keytab=$testdir/kdc/krb5.keytab test_environment armor armor_strategy=keytab
