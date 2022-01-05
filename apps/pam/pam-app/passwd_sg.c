#include <sys/cdefs.h>
#include <sys/param.h>

#include <err.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

//#include <security/openpam.h>
#include <security/pam_appl.h>

extern int conversation(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr);

static pam_handle_t *pamh;
static struct pam_conv pamc = {conversation, NULL};

static char *yp_domain;
static char *yp_host;

static void usage(void) {
  fprintf(stderr, "usage: passwd [-ly] [-d domain] [-h host] [user]\n");
  exit(1);
}

int main(int argc, char *argv[]) {
  char hostname[MAXHOSTNAMELEN];
  struct passwd *pwd = NULL; /* Keep compiler happy. */
  int o, pam_err;
  uid_t uid;

  while ((o = getopt(argc, argv, "d:h:loy")) != -1)
    switch (o) {
    case 'd':
      yp_domain = optarg;
      break;
    case 'h':
      yp_host = optarg;
      break;
    case 'l':
    case 'o':
    case 'y':
      /* compatibility */
      break;
    default:
      usage();
    }

  argc -= optind;
  argv += optind;

  uid = getuid();

  printf("Before switch\n");

  switch (argc) {
  case 0:
    if ((pwd = getpwuid(uid)) == NULL)
      errx(1, "who are you?");
    break;
  case 1:
    if ((pwd = getpwnam(*argv)) == NULL)
      errx(1, "%s: no such user", *argv);
    break;
  default:
    usage();
    exit(1);
    break;
  }

  if (uid != 0 && uid != pwd->pw_uid)
    errx(1, "permission denied");

  /* check where the user's from */

  fprintf(stderr, "%s\n", pwd->pw_passwd);

/*
 According to pwd.h these flags are "bogus", with nsswitch
 there are many possible source and they cannot be 
 represented in a small integer

  switch (pwd->pw_fields & _PWF_SOURCE) {
  case _PWF_FILES:
    fprintf(stderr, "Changing local password for %s\n", pwd->pw_name);
    break;
  case _PWF_NIS:
    fprintf(stderr, "Changing NIS password for %s\n", pwd->pw_name);
    break;
  default:
    // XXX: Green men ought to be supported via PAM.
    errx(1,
         "Sorry, `passwd' can only change passwords for local or NIS users.");
  }
*/

#define pam_check(func)                                                        \
  do {                                                                         \
    if (pam_err != PAM_SUCCESS) {                                              \
      if (pam_err == PAM_AUTH_ERR || pam_err == PAM_PERM_DENIED ||             \
          pam_err == PAM_AUTHTOK_RECOVERY_ERR)                                 \
        warnx("sorry");                                                        \
      else                                                                     \
        warnx("%s(): %s", func, pam_strerror(pamh, pam_err));                  \
      goto end;                                                                \
    }                                                                          \
  } while (0)

  /* initialize PAM */
  pam_err = pam_start("passwd", pwd->pw_name, &pamc, &pamh);
  pam_check("pam_start");

  pam_err = pam_set_item(pamh, PAM_TTY, ttyname(STDERR_FILENO));
  pam_check("pam_set_item");
  gethostname(hostname, sizeof hostname);
  pam_err = pam_set_item(pamh, PAM_RHOST, hostname);
  pam_check("pam_set_item");
  pam_err = pam_set_item(pamh, PAM_RUSER, getlogin());
  pam_check("pam_set_item");

  /* set YP domain and host */
  pam_err = pam_set_data(pamh, "yp_domain", yp_domain, NULL);
  pam_check("pam_set_data");
  pam_err = pam_set_data(pamh, "yp_server", yp_host, NULL);
  pam_check("pam_set_data");

  /* set new password */
  pam_err = pam_chauthtok(pamh, 0);
  pam_check("pam_chauthtok");

end:
  pam_end(pamh, pam_err);
  exit(pam_err == PAM_SUCCESS ? 0 : 1);
}

