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
#include <security/pam_appl.h>
#endif

#include <sys/stat.h>
#include <unistd.h>

#define MAX_USERFILE_SIZE 1024
#define USERSFILE "users"

bool auth_user(const char *, const char *);
void change_pass(const char *, const char *);
/**
 * @brief R
 *
 * @param user
 * @param password
 */
bool auth_user(const char *user, const char *password) {

/*
  FILE *f = fopen(USERSFILE, "r");
  char content[MAX_USERFILE_SIZE];
  int pos = 0;
  bool authenticated = false;

  int c;
  // Reading the file until EOF and filling content
  while ((c = fgetc(f)) != EOF) {
    content[pos++] = c;
  }

  char *userfield = strtok(content, ":");
  char *passfield = strtok(NULL, "\n");

  while (1) {
    if (strcmp(user, userfield) == 0 && strcmp(password, passfield) == 0) {
      authenticated = true;
      break;
    }
    userfield = strtok(NULL, ":");
    if (userfield == NULL)
      break;
    passfield = strtok(NULL, "\n");
    if (passfield == NULL)
      break;
  }
  return authenticated;

*/
}

void change_pass(const char *username, const char *password) {
  FILE *f = fopen(USERSFILE, "wr");
  char content[MAX_USERFILE_SIZE];
  int pos = 0;
  bool authenticated = false;

  int filepos = 0;

  int c;
  /* Reading the file until EOF and filling content */
  while ((c = fgetc(f)) != EOF) {
    content[pos++] = c;
  }

  char *userfield = strtok(content, ":");
  char *passfield = strtok(NULL, "\n");
  filepos += strlen(userfield) + strlen(passfield) + 2;
  while (1) {
    if (strcmp(username, userfield) == 0 && strcmp(password, passfield) == 0) {
      authenticated = true;
      break;
    }
    userfield = strtok(NULL, ":");
    if (userfield == NULL)
      break;
    passfield = strtok(NULL, "\n");
    if (passfield == NULL)
      break;
  }
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc,
                                   const char **argv) {
  int pam_code;

  const char *username = NULL;
  const char *password = NULL;

  //printf("\n\t+ (%s) Calling pam_get_user\n", __FUNCTION__);

  /* Asking the application for an  username */
  pam_code = pam_get_user(handle, &username, "Username: ");
  if (pam_code != PAM_SUCCESS) {
    fprintf(stderr, "Can't get username");
    return PAM_PERM_DENIED;
  }

  //printf("\n\t+ (%s) Calling pam_get_authtok\n", __FUNCTION__);

  /* Asking the application for a password */
  pam_code = pam_get_authtok(handle, PAM_AUTHTOK, &password, "Password: ");
  if (pam_code != PAM_SUCCESS) {
    fprintf(stderr, "Can't get password");
    return PAM_PERM_DENIED;
  }

  //printf("\n\t+ (%s) Recieved password: %s\n", __FUNCTION__, password);

  /* Checking the PAM_DISALLOW_NULL_AUTHTOK flag: if on, we can't accept empty
   * passwords */
  if (flags & PAM_DISALLOW_NULL_AUTHTOK) {
    if (password == NULL || strcmp(password, "") == 0) {
      fprintf(stderr, "Null authentication token is not allowed!.");
      return PAM_PERM_DENIED;
    }
  }

  /*Auth user reads a file with usernames and passwords and returns true if
   * username
   * and password are correct. Obviously, you must not save clear text passwords
   */
  if (auth_user(username, password)) {
    printf("Welcome, user");
    return PAM_SUCCESS;
  } else {
    fprintf(stderr, "Wrong username or password");
    return PAM_PERM_DENIED;
  }

  /* Auth user by calling auth_user provided by sg_daemon
   * must preform IPC with sg_daemon to pass and recieve requests
   */
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

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc,
                                const char **argv) {
  return PAM_SERVICE_ERR; 
}
