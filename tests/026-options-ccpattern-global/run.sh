#!/bin/sh

. $testdir/testenv.sh

$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
$kadmin -q 'modprinc -pwexpire never '$test_principal 2> /dev/null > /dev/null

test_run -auth -setcred -session $test_principal -run klist_c $pam_krb5 $test_flags ccname_template=FILE:${testdir}/kdc/krb5_cc_%U -- foo | sed s,_`id -u`,_'$UID',g
find kdc -name "krb5*cc*" | sed s,_`id -u`,_'$UID',g
rm -f ${testdir}/kdc/krb5_cc_`id -u`
test_run -auth -setcred -session $test_principal -run klist_c $pam_krb5 $test_flags ccname_template=DIR:${testdir}/kdc/krb5cc -- foo
find kdc -name "krb5*cc*"
rm -f -r ${testdir}/kdc/krb5cc
