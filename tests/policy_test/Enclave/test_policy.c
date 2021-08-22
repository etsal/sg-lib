#include "policy.h"
#include "sg_common.h"
sg_ctx_t ctx;

void ecall_test_policy() {

  login_t *admin_login = create_login("admin", "admin");
  login_t *incorrect_login = create_login("admin", "xxx");
  login_t *alice_login = create_login("alice", "password");
  
  init_new_policy(&ctx);

  int ret = put_user(&ctx, admin_login, alice_login);
  eprintf("put_user() returned %d\n", ret);
  assert(ret == 0); // This should succeed
  eprintf("\n\n");
/*
  ret = put_user(&ctx, admin_login, alice_login);
  eprintf("put_user() returned %d\n", ret);
  assert(ret != 0); // This should succeed
*/

  // This should fail at the authorization step
  ret = put_user(&ctx, alice_login, alice_login);
  eprintf("put_user() returned %d\n", ret);
  assert(ret == ACTION_NOPERM);
  eprintf("\n\n");


 
  free(admin_login);
  free(incorrect_login);
  free(alice_login);

  eprintf("COMPLETE TEST\n");

  return;

}
