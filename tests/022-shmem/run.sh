#!/bin/sh

. $testdir/testenv.sh

$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
$kadmin -q 'modprinc -pwexpire never '$test_principal 2> /dev/null > /dev/null

echo ""; echo "Forking, without use_shmem:"
test_run -fork -auth -setcred -session $test_principal -run klist_c $pam_krb5 $test_flags ccname_template=FILE:${testdir}/kdc/krb5cc_%U_XXXXXX test_environment -- foo
echo ""; echo "Forking, with use_shmem:"
test_run -fork -auth -setcred -session $test_principal -run grepenv.sh $pam_krb5 $test_flags ccname_template=FILE:${testdir}/kdc/krb5cc_%U_XXXXXX use_shmem test_environment -- foo

find ${testdir}/kdc -name "krb5cc*" -ls
