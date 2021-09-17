#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h> /* Necessary for reading secret password from console */

#include <unistd.h> //STDIN_FILENO

#define PASS_MAX_LEN 100

/**
 * @brief Reads a secret password from command line
 *
 * @param password[] String to be filled with the password
 *
 * @return Number of char read
 */
int readPass(char password[]) {
  static struct termios oldt, newt;
  int i = 0;
  int c;

  /*saving the old settings of STDIN_FILENO and copy settings for resetting*/
  tcgetattr(STDIN_FILENO, &oldt);
  newt = oldt;

  /*setting the approriate bit in the termios struct*/
  newt.c_lflag &= ~(ECHO);

  /*setting the new bits*/
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);

  /*reading the password from the console*/
  while ((c = getchar()) != '\n' && c != EOF && i < 100) {
    password[i++] = c;
  }
  password[i] = '\0';

  /*resetting our old STDIN_FILENO*/
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

  // printf("+ %s : end\n", __FUNCTION__);
  return strlen(password);
}

int readUser(char username[]) {
  int i = 0;
  int c;

  /*reading the password from the console*/
  while ((c = getchar()) != '\n' && c != EOF && i < 100) {
    username[i++] = c;
  }
  username[i] = '\0';
  
  return strlen(username);
}
