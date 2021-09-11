#include "policy.h"
#include "sg_common.h"

void basic_setup(sg_ctx_t *ctx) {
  login_t *admin_login = create_login("admin", "admin");
  login_t *alice_login = create_login("alice", "password");
  login_t *bob_login = create_login("bob", "password");

  init_sg_with_policy(ctx);

  int ret = put_user(ctx, admin_login, alice_login);
  assert(ret == 0); // This should succeed

  ret = put_user(ctx, admin_login, bob_login);
  assert(ret == 0); // This should succeed

  eprintf("Successfully added users 'alice' and 'bob'\n");
}

// Non-admin attempts to modify self policy (alice modify alice)
// Non-admin attempts to modify other policy (alice modify bob)
// Admin attempts to modify policy of non-existent user (admin modify claire)
// Admin modifies alice's policy (admin modift alice - give permission to modify
// bob's policy) Alice modifies bob's policy
void test_put_get_policy() {
  int ret;
  sg_ctx_t my_ctx;
  login_t *admin_login = create_login("admin", "admin");
  login_t *alice_login = create_login("alice", "password");
  login_t *bob_login = create_login("bob", "password");
  login_t *claire_login = create_login("claire", "password");
  char new_policy_entry[] = "home:bob/gp--";

  basic_setup(&my_ctx);
  eprintf("\nBasic setup done!\n\n");


  // (1) Alice puts in  bob's home - FAIL
  ret = put(&my_ctx, alice_login, "home:bob/test", "hello world", strlen("hello world"));
  assert(ret == ACTION_NOPERM_POLICY);
  eprintf("%d\n-\n", ret);

  // (2) Non-admin attempts to modify self policy (alice modify alice) - FAIL
  ret = append_policy(&my_ctx, alice_login, alice_login, new_policy_entry);
  assert(ret == ACTION_NOPERM_POLICY);
  eprintf("%d\n-\n", ret);


  // (3) Non-admin attempts to modify other policy (alice modify bob) - FAIL
  ret = append_policy(&my_ctx, alice_login, bob_login, "garbage");
  assert(ret == ACTION_NOPERM_POLICY);
  eprintf("%d\n-\n", ret);


  // (4) Admin attempts to modify policy of non-existent user (admin modify claire)
  // - FAIL
  ret = append_policy(&my_ctx, admin_login, claire_login, new_policy_entry);
  assert(ret == NOEXIST_POLICY);
  eprintf("%d\n-\n", ret);

  // (5) Admin modifies alice's policy - SUCCESS
  ret = append_policy(&my_ctx, admin_login, alice_login, new_policy_entry);
  assert(ret == 0);
  eprintf("%d\n-\n", ret);

  // (6 - 1) Alice puts in  bob's home using policy change made by admin - SUCCESS
  ret = put(&my_ctx, alice_login, "home:bob/test", "hello world", strlen("hello world"));
  assert(ret == 0);
  eprintf("%d\n-\n", ret);
}

void test_put_get_user() {
  sg_ctx_t my_ctx;
  login_t *admin_login = create_login("admin", "admin");
  login_t *incorrect_login = create_login("admin", "xxx");
  login_t *alice_login = create_login("alice", "password");
  login_t *bob_login = create_login("bob", "password");

  init_sg_with_policy(&my_ctx);

  int ret = put_user(&my_ctx, admin_login, alice_login);
  eprintf("put_user() returned %d\n", ret);
  assert(ret == 0); // This should succeed
  eprintf("\n\n");
  /*
    ret = put_user(&ctx, admin_login, alice_login);
    eprintf("put_user() returned %d\n", ret);
    assert(ret != 0); // This should succeed
  */

  // This should fail at the authorization step
  ret = put_user(&my_ctx, alice_login, alice_login);
  eprintf("put_user() returned %d\n", ret);
  assert(ret == ACTION_NOPERM_POLICY);
  eprintf("\n\n");

  free(admin_login);
  free(incorrect_login);
  free(alice_login);

  eprintf("COMPLETE TEST\n");

  return;
}

void ecall_test_policy() { 
//  test_put_get_user(); 
  test_put_get_policy();  
}
