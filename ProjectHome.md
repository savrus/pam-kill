PAM module to kill all user's processes he/she is no longer logged in the system. Affects only uids between startuid and enduid (you can set enduid to zero for infinite end).

Here is a sample PAM config line:

> session    required     /lib/security/pam\_kill.so startuid=1000 enduid=2000

This was originally created for a public ssh server at Moscow State University dorms.