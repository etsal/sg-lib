#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/types.h>

int main(int argc, char *argv[]) {
  struct passwd pd;
  struct passwd *pwdptr = &pd;
  struct passwd *tempPwdPtr;
  char pwdbuffer[200];
  int pwdlinelen = sizeof(pwdbuffer);

  if ((getpwnam_r("root", pwdptr, pwdbuffer, pwdlinelen, &tempPwdPtr)) != 0)
    perror("getpwnam_r() error.");
  else {
    printf("\nThe user name is: %s\n", pd.pw_name);
    printf("The user id   is: %u\n", pd.pw_uid);
    printf("The group id  is: %u\n", pd.pw_gid);
    printf("The initial directory is:    %s\n", pd.pw_dir);
    printf("The initial user program is: %s\n", pd.pw_shell);
  }

  printf("Pointer values pwdptr %x &tempPwdPtr %x tempPwd %x\n", pwdptr, &tempPwdPtr, tempPwdPtr);

  printf("Buffer %s %s\n", pwdbuffer, pwdbuffer+5);
  return 0;
}
