#include <security/pam_modules.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#ifdef HAVE_PAM_EXT
#include <security/pam_ext.h>
#endif
#ifdef HAVE_PAM_APPL
#else
#include <security/pam_appl.h>
#endif

#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "policy_errlist.h"
#include "sgd_request.h"

#include <pwd.h>

#define MAX_USERFILE_SIZE 1024
#define USERSFILE "users"

//#define DEBUG_AUTH 1


int sg_ret = 0;

/* return 0 on success, 1 on error
 * on success, response will be populated
 */
int client_make_request(int action, struct request_msg *request,
                         struct response_msg **response) {

  *response = init_response_msg();

  int ret = sgd_sync_make_request(&sg_ret, request, *response);
  if (ret == 0) {
    goto exit;
  }
  free(*response);
  *response = NULL;

exit:
  return ret;
}

int auth_user(const char *user, const char *password) {

  int ret;

  struct response_msg *response;
  struct request_msg *request =
      gen_request_msg(AUTH_USER, user, password, strlen(password) + 1);

  ret = client_make_request(0, request, &response);
  if (ret) {
    goto exit;
  }

  if (response->ret == ACTION_SUCCESS) {
    ret = 1;
  } else {
    ret = 0;
  }

  free(response);

exit:
  free(request);
  return ret;
}


PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc,
                                   const char **argv) {
  int pam_code;

  const char *username = NULL;
  const char *password = NULL;
  struct passwd *pwd;
#ifdef DEBUG_AUTH
  printf("\n\t+ (%s) Calling pam_get_user\n", __FUNCTION__);
#endif

  /* Asking the application for an  username */
  pam_code = pam_get_user(handle, &username, "Username: ");
  if (pam_code != PAM_SUCCESS) {
    fprintf(stderr, "Can't get username");
    return PAM_PERM_DENIED;
  }

  if ((pwd = getpwnam(username)) == NULL) {
    return (PAM_USER_UNKNOWN);
  }

#ifndef DEBUG_AUTH
  printf("\n\t+ (%s) Calling pam_get_authtok\n", __FUNCTION__);
#endif

  /* Asking the application for a password */
  pam_code = pam_get_authtok(handle, PAM_AUTHTOK, &password, "Password: ");
  if (pam_code != PAM_SUCCESS) {
    fprintf(stderr, "Can't get password");
    return PAM_PERM_DENIED;
  }

#ifdef DEBUG_AUTH
  printf("\n\t+ (%s) Recieved password: %s\n", __FUNCTION__, password);
#endif

  /* Checking the PAM_DISALLOW_NULL_AUTHTOK flag: if on, we can't accept empty
   * passwords */
  if (flags & PAM_DISALLOW_NULL_AUTHTOK) {
    if (password == NULL || strcmp(password, "") == 0) {
      fprintf(stderr, "Null authentication token is not allowed!.");
      return PAM_PERM_DENIED;
    }
  }

#ifdef DEBUG_AUTH
  printf("\n\t+ (%s) Calling auth_user \n", __FUNCTION__);
#endif

  /*Auth user reads a file with usernames and passwords and returns true if
   * username and password are correct. Obviously, you must not save clear text
   * passwords
   */
  if (auth_user(username, password)) {
#ifdef DEBUG_AUTH
    printf("Welcome, user\n");
#endif
    return PAM_SUCCESS;
  } else {
#ifdef DEBUG_AUTH
    fprintf(stderr, "Wrong username or password\n");
#endif
  return PAM_PERM_DENIED;
  }

}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc,
                                const char **argv) {
  return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
                              const char **argv) {
  return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc,
                                   const char **argv) {
  return PAM_SERVICE_ERR;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc,
                                    const char **argv) {
  return PAM_SERVICE_ERR;
}

/*
 * The PAM library calls this function twice. The first time with
 * PAM_PRELIM_CHECK and then, if the modules does not return PAM_TRY_AGAIN,
 * subsequently iwth PAM_UPDATE_AUTHTOK. Only on the second call does the
 * authorization token change
 *
 * If we are not root, we must authenticate old password
 * -> this seems to be how the pam_unix.so and pam_ldap.so preform this function
 *
 */
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
                                const char **argv) {
  const char *user, *old_pass, *new_pass;
  int retval;

  retval = pam_get_user(pamh, &user, NULL);
  if (retval != PAM_SUCCESS) {
    return (retval);
  }

  fprintf(stderr, "Got user :%s\n", user);

  if (flags & PAM_PRELIM_CHECK) {
    fprintf(stderr, "PRELIM round\n");

    if (getuid() == 0) {
      /* root doesn't need old password */
      return (pam_set_item(pamh, PAM_OLDAUTHTOK, ""));
    } else {
      retval = pam_get_authtok(pamh, PAM_OLDAUTHTOK, &old_pass, NULL);
      if (retval != PAM_SUCCESS)
        return (retval);
    }

    // Got old password
    fprintf(stderr, "Old password: %s\n", old_pass);

    // Verify old password

    return (retval);
  } else if (flags & PAM_UPDATE_AUTHTOK) {
    fprintf(stderr, "UPDATE round\n");

    retval = pam_get_authtok(pamh, PAM_OLDAUTHTOK, &old_pass, NULL);
    if (retval != PAM_SUCCESS)
      return (retval);
    fprintf(stderr, "Got old password\n");

    for (;;) {
      retval = pam_get_authtok(pamh, PAM_AUTHTOK, &new_pass, NULL);
      if (retval != PAM_TRY_AGAIN)
        break;
      pam_error(pamh, "Mismatch; try again, EOF to quit.");
    }
    fprintf(stderr, "Got new password\n");
    if (retval != PAM_SUCCESS) {
      //PAM_VERBOSE_ERROR("Unable to get new password");
      fprintf(stderr, "Unable to get new password\n");
      return retval;
    }

    // Update password
  }
  return PAM_SERVICE_ERR;
}
