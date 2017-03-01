This is a major rewrite of pam_krb5afs.  Call it 2.x, for lack of a better term.

* Compared to the earlier releases, this tree builds a single module which
  "knows" how to do everything which is knowable at compile-time.
* Configuration options which can now be set as library defaults in the
  system-wide krb5.conf are now largely ignored by the module.

Standard options:

* **debug**

  Log debugging messages at LOG_DEBUG priority.

* **debug_sensitive**

  Even log passwords when logging debugging messages at LOG_DEBUG priority.

* **no_warn**

  When authenticating, don't warn the user about an expired password.

* **use_authtok**

  When changing passwords, never prompt for password data.  Instead, use
  data stored by a previously-called module.

* **use_first_pass**

  When authenticating, never prompt for password data.  Instead, use a
  password which was stored by a previously-called module.

* **try_first_pass**

  When authenticating, first try to authenticate using the password which
  was stored by a previously-called module.  If it fails, then prompt for
  the correct password and try again.

Recognized options (in krb5.conf's appdefaults/pam section, and command-line):

* **always_allow_localname**

  Always allow the local user, as derived from the principal name being
  authenticated, to access the account, even when not explicitly listed in
  the .k5login file or its equivalent(s).

* **armor**

  Attempt to use a secondary credential cache for armoring exchanges with
  the KDC.

* **armor_strategy**

  Override how the module attempts to obtain credentials for use as armor.
  By default, the module supports these methods:
    keytab    Use the default or configured keytab to get a service's TGT.
    pkinit    Use anonymous PKINIT.
  The default list of methods, and their order, is noted in the manual pages.

* **banner**=Kerberos

  When changing passwords, tell users that they are changing their Kerberos
  passwords (unset to avoid using any term other than "password").

* **ccache_dir**=/tmp

  Directory in which to store ccache and ticket files.

* **ccname_template**=FILE:%d/krb5cc_%U_XXXXXX

  Location of the user's v5 ccache files.  If not configured, the module will
  attempt to read the library's default.

* **chpw_prompt**

  Allow expired passwords to be changed during authentication attempts.  While
  this is the traditional behavior exhibited by "kinit", it is inconsistent
  with the behavior expected by PAM, which expects authentication to (appear to)
  succeed and to have password expiration be flagged by the account management
  function.  Some applications which don't handle password expiration will fail
  incorrectly if the user's password is correct but expired, and setting this
  flag attempts to work around the bug.

* **cred_session**

  Control whether or not pam_krb5 will create/remove credential caches when
  the calling application initializes or deletes PAM credentials.  The module
  will do so when the application opens and closes the PAM session, and this
  is usually harmless, so it is typically enabled by default.

* **debug**

  debug = service1 service2

  Log debug messages to syslog with priority LOG_DEBUG.

* **external**

  external = service1 service2

  Attempt to reuse credentials stored in a ccache pointed to by the KRB5CCNAME
  variable in the PAM environment.  This is mainly useful for situations where
  the calling application authenticated the user using GSSAPI, the user
  delegated credentials to the calling application, and you're using pam_krb5
  to obtain a v4 Kerberos ticket via krb524, or AFS tokens.  The calling
  application MUST ensure that KRB5CCNAME points to a ccache which should be
  used for the authenticating user.  A default list of services can be set at
  compile-time.

* **ignore_afs**

  Disable the default behavior of attempting to obtain tokens for the local
  AFS cell on behalf of clients.

* **ignore_k5login**

  Disables additional authorization checks using the krb5_kuserok() function,
  which typically checks the user's .k5login file.

* **ignore_unknown_principals**
  **ignore_unknown_spn**
  **ignore_unknown_upn**

  Controls whether or not users with unknown principal names should trigger
  a PAM_IGNORE error instead of a PAM_USER_UNKNOWN error.

* **initial_prompt**

  Controls whether or not pam_krb5 should ask for the user's password, or let
  libkrb5 do it as needed.

* **keytab**=/etc/krb5.keytab

  Default keytab to use when validating initial credentials.  Can be overridden
  at configure-time.

* **mappings** = regex regex [regex regex...]

  Specifies that pam_krb5 should derive the user's principal name from the Unix
  user name by first checking if the user name matches the first regex, and
  if it matches, formulating a principal name using the second regex.  Multiple
  pairs of regular expressions can be used.
  For example,

    mappings = ^EXAMPLE\\(.*)$ $1@EXAMPLE.COM

  would map any user with a name of the form "EXAMPLE\whatever" to a principal
  name of "whatever@EXAMPLE.COM".  This is primarily targeted at allowing
  pam_krb5 to be used to authenticate users whose user information is provided
  by winbindd.
  Note that this will frequently require the reverse to be configured by
  setting up an auth_to_local rule elsewhere in krb5.conf.

* **minimum_uid**=NUMBER

  Minimum UID which the user must have before pam_krb5.so will attempt to
  authenticate that user, otherwise it will ignore the user.

* **multiple_ccaches**

  Specifies that pam_krb5 should maintain multiple credential caches for
  the application, which sets credentials and opens a PAM session, but
  sets the KRB5CCNAME variable after doing only one of the two.  This
  option is usually not necessary for most services, but the option is
  provided as a workaround.

* **no_validate**

  no_validate = service1 service2

  Don't try to validate initial credentials.

* **no_user_check**

  Go ahead and authenticate users for whom getpwnam() returns no information.
  Credential cache and ticket files will be created and owned by the current
  user and group ID instead of the user's.

* **null_afs**

  Attempt to get credentials for AFS by guessing a service name of the form
  afs@REALM first, and then one of the form afs/cell@REALM, rather than
  proceeding in the opposite order.

* **pkinit_identity**=LOCATION (Heimdal-specific)

  Specify the location of the user's private key and certificate information,
  in the same format which would be passed to kinit as an argument for its
  -C/--pk-user command-line option.

* **pkinit_flags**=NUMBER (Heimdal-specific)

  Specify a flags value to pass to libkrb5, useful mainly for debugging.

* **preauth_options**=OPT=VAL[,...] (MIT-specific)

  Specify arbitrary preauthentication options to pass to libkrb5, useful
  mainly for debugging.

* **realm**=REALM

  Override the default realm.

* **subsequent_prompt**

  Controls whether or not pam_krb5 should just return the PAM_AUTHTOK when
  libkrb5 requests that pam_krb5 get information from the user.

* **tokens**

  tokens = service1 service2

  Create a new AFS PAG and obtain AFS tokens during the authentication phase.
  By default, tokens are obtained for the local cell (and the cell which
  contains the user's home directory, if they're not the same).

* **token_strategy**

  Override how the module attempts to get credentials and set AFS tokens.
  By default, the module supports these methods:

    * 2b
      Get krb5 credentials, and use the "2b" rxkad token format, which is only
      supported in OpenAFS 1.2.8 and later.
    * rxk5
      Get krb5 credentials, and use the rxk5 token format, which may be
      supported in OpenAFS 1.6 and later.

  The default list of methods, and their order, is noted in the manual pages.

* **trace**

  trace = service1 service2

  Log libkrb5 trace messages to syslog with priority LOG_DEBUG, if the
  Kerberos implementation provides a means to let pam_krb5 do so.

* **use_shmem**

  use_shmem = service1 service2

  Pass credentials from authentication to session management using shared
  memory instead of PAM data items.  This allows authentication and session-
  managment to be performed in different processes, so long as the PAM
  environment is correctly propagated from one to the other.  A default list
  of services can be set at compile-time.

* **validate_user_user**

  validate_user_user = service1 service2

  If validation fails due to permissions problems, attempt to validate initial
  credentials using previously-obtained credentials in the default ccache.

Configuration file only:

* **afs_cells** = cell1 cell2 cell3 cell4=afs/cell4@EXAMPLE.COM

This module is hosted on pagure.io.  For more information, point a web browser
at "https://pagure.io/pam_krb5/".
