
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
      gen_request_msg(AUTH_USER, name, password, strlen(password) + 1);

  ret = client_make_request(request, &response);
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

void get_user_by_name(const char *user, struct passwd *pwd) {
  int ret;

  struct response_msg *response;
  struct request_msg *request =
      gen_request_msg(GET_USER_BY_NAME, name, NULL, 0);

  ret = client_make_request(request, &response);
  if (ret) {
    goto exit;
  }

  // TODO: Do something with response

  free(response);

exit:
  free(request);
  return ret;

}

void get_user_by_id(int id, struct passwd *pwd) {
  int ret;

  
  char id_buf[16];
  snprintf(id_buf, 15, "%d", id);

  struct response_msg *response;
  struct request_msg *request =
      gen_request_msg(GET_USER_BY_ID, id_buf, NULL, 0);

  ret = client_make_request(request, &response);
  if (ret) {
    return ret;
  }

  //TODO: Do something with response

  free(response);
}
