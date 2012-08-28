#!/bin/sh

. $testdir/testenv.sh

$kadmin -q 'cpw -pw foo '$test_principal 2> /dev/null > /dev/null
$kadmin -q 'modprinc -pwexpire never '$test_principal 2> /dev/null > /dev/null

keyctl new_session > /dev/null
klist -c KEYRING:foo > /dev/null 2> klist.keyring.out
keyctl show @s > keyring.before
if ! grep -q -i 'unknown credential cache type' $KRB5RCACHEDIR/klist.keyring.out ; then
	test_run -auth -setcred -session $test_principal -run klist_c $pam_krb5 $test_flags ccname_template=KEYRING:krb5cc_%U_XXXXXX -- foo
else
cat << EOF
Calling module `pam_krb5.so'.
`Password: ' -> `foo'
AUTH	0	Success
ESTCRED	0	Success
KEYRING:krb5cc_$UID_XXXXXX
DELCRED	0	Success
EOF
fi
keyctl show @s > keyring.after
cmp keyring.before keyring.after
