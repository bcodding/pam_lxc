/* pam_lxc module */

#include "config.h"

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION
#define PAM_SM_PASSWORD

#include <sys/types.h>
#include <sys/syslog.h>
#include <linux/stddef.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

/* --- session management --- */

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
		    int argc, const char **argv)
{
    const char *user;
    pid_t pid, init_pid;
    int ret;

    ret = pam_get_user(pamh, &user, 0);
    if (ret != PAM_SUCCESS)
        return ret;

    if (strcmp(user,"root") == 0)
        return PAM_SUCCESS;

    init_pid = get_init_pid(user);
    if (init_pid < 0) {
        pam_info(pamh, "Unable to attach to container %s", user);
        //pam_prompt(pamh, PAM_TEXT_INFO, 0, "pam_lxc cannot find a suitable contianer for %s\n", user);
        pam_syslog(pamh, LOG_ERR, "cannot find a suitable contianer for %s\n", user);
        pam_syslog(pamh, LOG_ERR, "failed to get the init pid\n");
        return PAM_SESSION_ERR;
    }

    ret = lxc_attach(init_pid);
    if (ret < 0) {
        pam_syslog(pamh, LOG_ERR, "failed to enter the namespace, error %d\n", ret);
        return PAM_SESSION_ERR;
    }

    pid = fork();
    if (pid == -1) {
        pam_syslog(pamh, LOG_ERR, "fork failed\n");
        return PAM_SESSION_ERR;
    } else if (pid != 0) {
        pam_syslog(pamh, LOG_INFO, "migrated %d into container %d\n", pid, init_pid);
        exit(0);
    }

    return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
		     int argc, const char **argv)
{
     return PAM_SUCCESS;
}
/* end of module definition */ 
/* static module data */
#ifdef PAM_STATIC
struct pam_module _pam_lxc_modstruct = {
    "pam_lxc",
    NULL,
    NULL,
    NULL,
    pam_sm_open_session,
    pam_sm_close_session,
    NULL
};
#endif
