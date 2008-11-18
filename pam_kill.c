/* PAM Kill module

   This module kill's all user's processes when he no longer is logged in
      
   Here is sample PAM config line:

   session    required     /lib/security/pam_kill.so startuid=1000 enduid=2000  
   
   Released under the GNU LGPL version 2 or later
   Originally written by Ruslan Savchenko <savrus@mexmat.net> December 2006
   Structure taken from pam_mkhomedir by Jason Gunthorpe
     <jgg@debian.org> 1999

*/

#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <syslog.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <utmp.h>


#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/_pam_macros.h>

struct pam_params
{
	uid_t start_uid;
	uid_t end_uid;
};


static void
_pam_parse_params(int argc, const char **argv, struct pam_params *p)
{
	for (; argc-- > 0; ++argv)
	{
		if (strncmp (*argv, "startuid=",9) == 0)
			p->start_uid = strtol (*argv + 9, NULL, 10);
		else if (strncmp (*argv, "enduid=", 7) == 0)
			p->end_uid = strtol (*argv + 7, NULL, 10);
	}
}



PAM_EXTERN int
pam_sm_close_session (pam_handle_t *pamh, int flags, int argc,
		     const char **argv)
{
	int retval;
	const void *user;
	const struct passwd *pwd;
	struct pam_params param =
	{
		.start_uid = 1000,
		.end_uid = 0,
	};
	char srvstr[50];
	const char *service;
	int nlogins = 0;
	struct utmp *uent;
	pid_t uid;
	
	
	if (pam_get_item (pamh, PAM_SERVICE, (const void **) &service) != PAM_SUCCESS)
		service = "";
	
	/* Start logging */
	snprintf (srvstr, sizeof (srvstr), "%s[%d]: (pam_setquota) ", service, getpid ());
	openlog(srvstr,0,LOG_AUTHPRIV);

	/* Parse values */
	_pam_parse_params(argc, argv, &param);

	/* Determine the user name so we can get the home directory */
	retval = pam_get_item(pamh, PAM_USER, &user);
	if (retval != PAM_SUCCESS || user == NULL ||
		*(const char *)user == '\0')
	{
		syslog(LOG_NOTICE, "user unknown");
		return PAM_USER_UNKNOWN;
	}

	/* Get the password entry */
	pwd = getpwnam(user);
	if (pwd == NULL)
	{
		return PAM_CRED_INSUFFICIENT;
	}
	
	if ((pwd->pw_uid < param.start_uid)
		|| ((param.end_uid >= param.start_uid)
			&& (param.start_uid != 0)
			&& (pwd->pw_uid > param.end_uid)))
		return PAM_SUCCESS;

	uid = pwd->pw_uid;
	setutent();
	
	while ((uent = getutent()) != NULL){
		if (uent->ut_type == USER_PROCESS){
			pwd = getpwnam(uent->ut_user);
			if (pwd->pw_uid == uid){
				nlogins++;
				if (nlogins == 1)
					return PAM_SUCCESS;
			}				
		}
	}

	if (!fork()){
		setuid(pwd->pw_uid);
		//setreuid(pwd->pw_uid,pwd->pw_uid);
		//if (getuid() == pwd->pw_uid)
			kill(-1,SIGKILL);
		sleep(1);
		exit(0);
	}

	sleep(1);
	
	return PAM_SUCCESS;	
}


PAM_EXTERN
int pam_sm_open_session (pam_handle_t * pamh, int flags,
			  int argc, const char **argv)
{
	return PAM_SUCCESS;
}

#ifdef PAM_STATIC

/* static module data */
struct pam_module _pam_kill_modstruct =
{
	   "pam_kill",
	   NULL,
	   NULL,
	   NULL,
	   pam_sm_open_session,
	   pam_sm_close_session,
	   NULL
};

#endif
