

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

