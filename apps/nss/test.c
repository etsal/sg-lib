#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/types.h>

int main(int argc, char *argv[]) {
  struct passwd pd;
  struct passwd *pwdptr = &pd;
  struct passwd *tempPwdPtr = &pd;
  char pwdbuffer[200];
  int pwdlinelen = sizeof(pwdbuffer);


  if (argc != 2)
    return 1;

//  printf("Pointer values pwdptr %x &tempPwdPtr %x tempPwd %x\n\n", pwdptr, &tempPwdPtr, tempPwdPtr);


  int ret = getpwnam_r(argv[1], pwdptr, pwdbuffer, pwdlinelen, &tempPwdPtr);
//  printf("getpwnam_r ret = %d\n", ret);

  if(tempPwdPtr != NULL) {
    printf("User found!\n");
    printf("The user name is: %s\n", pd.pw_name);
    printf("The user id   is: %u\n", pd.pw_uid);
    printf("The group id  is: %u\n", pd.pw_gid);
    printf("The initial directory is:    %s\n", pd.pw_dir);
    printf("The initial user program is: %s\n", pd.pw_shell);
  } else {
    printf("User NOT found!\n");
  }

  //printf("Pointer values pwdptr %x &tempPwdPtr %x tempPwd %x\n", pwdptr, &tempPwdPtr, tempPwdPtr);

  // printf("Buffer %s %s\n", pwdbuffer, pwdbuffer+5);
  return 0;
}
