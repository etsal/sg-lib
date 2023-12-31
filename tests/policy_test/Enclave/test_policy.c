
#include "policy.h"
#include "sg_common.h"

void basic_setup(sg_ctx_t *ctx) {

  init_sg_with_policy(ctx);

  login_t *admin_login = create_login(ctx, "admin", "admin");
  login_t *alice_login = create_login(ctx, "alice", "password");
  login_t *bob_login = create_login(ctx, "bob", "password");


  int ret = put_user(ctx, admin_login, alice_login);
  assert(ret == 0); // This should succeed

  ret = put_user(ctx, admin_login, bob_login);
  assert(ret == 0); // This should succeed

  eprintf("+ Basic setup complete ... Successfully added users 'alice' and 'bob'\n");
}

// Non-admin attempts to modify self policy (alice modify alice)
// Non-admin attempts to modify other policy (alice modify bob)
// Admin attempts to modify policy of non-existent user (admin modify claire)
// Admin modifies alice's policy (admin modift alice - give permission to modify
// bob's policy) Alice modifies bob's policy
void test_put_get_policy() {
  int ret;
  sg_ctx_t my_ctx;

  basic_setup(&my_ctx);
 
  my_ctx.next_uid = 1;

  login_t *admin_login = create_login(&my_ctx, "admin", "admin");
  login_t *alice_login = create_login(&my_ctx, "alice", "password");
  login_t *bob_login = create_login(&my_ctx, "bob", "password");
  login_t *claire_login = create_login(&my_ctx, "claire", "password");
  char new_policy_entry[] = "home:bob/gp--";

  eprintf("+ Generated logins\n");

 // (1) Alice puts in  bob's home - FAIL
  ret = put(&my_ctx, alice_login, "home:bob/test", "hello world", strlen("hello world"));
  if (ret != ACTION_NOPERM_POLICY) {
    eprintf("+ Test failed with %d\n", ret);
    assert(1);
  }

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

/*
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
*/

// Non-admin attempts to modify self policy (alice modify alice)
// Non-admin attempts to modify other policy (alice modify bob)
// Admin attempts to modify policy of non-existent user (admin modify claire)
// Admin modifies alice's policy (admin modift alice - give permission to modify
// bob's policy) Alice modifies bob's policy
void test_get_policy() {
  int ret;
  sg_ctx_t my_ctx;

  basic_setup(&my_ctx);
 
  my_ctx.next_uid = 1;

  login_t *admin_login = create_login(&my_ctx, "admin", "admin");
  char new_policy_entry[] = "home:bob/gp--";

  eprintf("+ Generated logins\n");
  login_t *found;

  ret = get_user_by_name(&my_ctx, admin_login, "alice", &found);
  if (ret != 0) {
    eprintf("+ get_user_by_name failed with %d\n", ret);
    assert(1);
  }
  eprintf("user %s uid %d\n\n\n", found->user, found->uid);

  free(found);
  ret = get_user_by_id(&my_ctx, admin_login, 3, &found);
  if (ret != 0) {
    eprintf("+ get_user_by_name failed with %d\n", ret);
    assert(1);
  }
  eprintf("user %s uid %d\n", found->user, found->uid);

}


void ecall_test_policy() { 
//  test_put_get_user(); 
  test_get_policy();  
}
