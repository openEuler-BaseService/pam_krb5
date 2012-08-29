#!/bin/sh

. $testdir/testenv.sh

$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
$kadmin -q 'modprinc -pwexpire never '$test_principal 2> /dev/null > /dev/null

test_run -auth -setcred -session $test_principal -run klist_c $pam_krb5 $test_flags ccname_template=FILE:${testdir}/kdc/krb5cc_%U -- foo
find ${testdir}/kdc -name "krb5cc*" -ls
test_run -auth -setcred -session $test_principal -run klist_c $pam_krb5 $test_flags ccname_template=DIR:${testdir}/kdc/krb5 -- foo
find ${testdir}/kdc -name "krb5cc*" -ls
